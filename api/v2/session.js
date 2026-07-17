const { getDevice, isUserBanned, saveLease, touchDevice } = require("../../lib/redis");
const { failure, requirePost } = require("../../lib/http");
const { checkDistributedRateLimit, clientIp } = require("../../lib/rate-limit");
const {
  createSessionEnvelope,
  getBuildConfig,
  normalizeBuildId,
  normalizeFingerprint,
  normalizeNonce,
  safeEqualHex,
  sha256,
  verifyOrigin,
} = require("../../lib/security");

module.exports = async (req, res) => {
  if (!requirePost(req, res)) return;
  if (!verifyOrigin(req)) return failure(res, 403, "ORIGIN_DENIED", "请求来源无效");

  try {
    const ip = clientIp(req);
    const fingerprint = normalizeFingerprint(req.body?.fingerprint);
    const buildId = normalizeBuildId(req.body?.build_id);
    const nonce = normalizeNonce(req.body?.nonce);
    const token = String(req.body?.device_token || "");

    const [ipRate, deviceRate] = await Promise.all([
      checkDistributedRateLimit("session-ip", ip, 30, 60),
      checkDistributedRateLimit("session-device", fingerprint, 12, 60),
    ]);
    if (!ipRate.allowed || !deviceRate.allowed) {
      return failure(res, 429, "RATE_LIMITED", "请求过于频繁");
    }

    const device = await getDevice(fingerprint);
    if (!device || !device.token_hash || !safeEqualHex(device.token_hash, sha256(token))) {
      return failure(res, 403, "ACTIVATION_REQUIRED", "需要重新激活");
    }
    if (device.status === "banned" || (device.qq && await isUserBanned(device.qq))) {
      return failure(res, 403, "DEVICE_BANNED", "设备已被停用");
    }

    const session = createSessionEnvelope({
      fingerprint,
      buildId,
      nonce,
      config: getBuildConfig(buildId),
    });
    await Promise.all([saveLease(session), touchDevice(fingerprint)]);
    return res.status(200).json({ ok: true, session });
  } catch (error) {
    if (["INVALID_FINGERPRINT", "INVALID_BUILD_ID", "INVALID_NONCE"].includes(error.message)) {
      return failure(res, 400, error.message, "请求参数无效");
    }
    if (error.message === "BUILD_NOT_ALLOWED") {
      return failure(res, 403, error.message, "当前版本未启用");
    }
    console.error("v2 session error:", error);
    return failure(res, 500, "SERVER_ERROR", "服务器内部错误");
  }
};
