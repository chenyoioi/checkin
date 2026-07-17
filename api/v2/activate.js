const crypto = require("crypto");
const { activateDevice, getDevice, isUserBanned, saveLease } = require("../../lib/redis");
const { failure, requirePost } = require("../../lib/http");
const { checkDistributedRateLimit, clientIp } = require("../../lib/rate-limit");
const {
  base64url,
  createSessionEnvelope,
  getBuildConfig,
  normalizeBuildId,
  normalizeFingerprint,
  normalizeNonce,
  sha256,
  verifyLicense,
  verifyOrigin,
} = require("../../lib/security");

module.exports = async (req, res) => {
  if (!requirePost(req, res)) return;
  if (!verifyOrigin(req)) return failure(res, 403, "ORIGIN_DENIED", "请求来源无效");

  try {
    const ip = clientIp(req);
    const rate = await checkDistributedRateLimit("activate", ip, 5, 60);
    if (!rate.allowed) return failure(res, 429, "RATE_LIMITED", "请求过于频繁");

    const fingerprint = normalizeFingerprint(req.body?.fingerprint);
    const buildId = normalizeBuildId(req.body?.build_id);
    const nonce = normalizeNonce(req.body?.nonce);
    const licenseKey = String(req.body?.license_key || "");
    if (!verifyLicense(fingerprint, licenseKey)) {
      return failure(res, 403, "INVALID_LICENSE", "授权码无效");
    }

    const device = await getDevice(fingerprint);
    if (!device) return failure(res, 403, "DEVICE_NOT_REGISTERED", "设备尚未授权");
    if (device.status === "banned" || (device.qq && await isUserBanned(device.qq))) {
      return failure(res, 403, "DEVICE_BANNED", "设备已被停用");
    }
    const suppliedHash = sha256(licenseKey.replace(/\s/g, ""));
    if ((device.license_hash && device.license_hash !== suppliedHash) ||
        (device.license_key && sha256(device.license_key.replace(/\s/g, "")) !== suppliedHash)) {
      return failure(res, 403, "LICENSE_MISMATCH", "授权码与设备不匹配");
    }

    const token = base64url(crypto.randomBytes(32));
    await activateDevice(fingerprint, sha256(token));
    const session = createSessionEnvelope({
      fingerprint,
      buildId,
      nonce,
      config: getBuildConfig(buildId),
    });
    await saveLease(session);
    return res.status(200).json({ ok: true, device_token: token, session });
  } catch (error) {
    if (["INVALID_FINGERPRINT", "INVALID_BUILD_ID", "INVALID_NONCE"].includes(error.message)) {
      return failure(res, 400, error.message, "请求参数无效");
    }
    if (error.message === "BUILD_NOT_ALLOWED") {
      return failure(res, 403, error.message, "当前版本未启用");
    }
    console.error("v2 activate error:", error);
    return failure(res, 500, "SERVER_ERROR", "服务器内部错误");
  }
};
