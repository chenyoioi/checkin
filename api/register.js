// api/register.js - AstrBot 插件注册设备码接口
//
// 插件发送: {
//   admin_key: "xxx",       // 管理密钥
//   device_id: "xxx",
//   qq: "xxx",
//   qq_name: "xxx",
//   license_key: "base64..."
// }

const { registerDevice, getDevice, countUserDevices, isUserBanned } = require("../lib/redis");
const { checkRateLimit, getClientIP } = require("./_lib/ratelimit");
const { normalizeFingerprint, sha256, verifyLicense, verifyOrigin } = require("../lib/security");

const MAX_DEVICES_PER_USER = 3;
const ADMIN_KEY = process.env.ADMIN_KEY;

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Method not allowed" });
  }
  if (!verifyOrigin(req)) {
    return res.status(403).json({ ok: false, message: "请求来源无效" });
  }

  // 速率限制: 每个 IP 每分钟最多 10 次 (注册接口更严格)
  const ip = getClientIP(req);
  const rl = checkRateLimit(ip, 10, 60000);
  if (!rl.allowed) {
    return res.status(429).json({ ok: false, message: "请求过于频繁" });
  }

  try {
    const { admin_key, device_id, qq, qq_name, license_key } = req.body || {};

    if (!ADMIN_KEY) {
      return res.status(503).json({ ok: false, message: "服务端未配置管理密钥" });
    }
    if (admin_key !== ADMIN_KEY) {
      return res.status(403).json({ ok: false, message: "无权限" });
    }

    if (!device_id) {
      return res.status(400).json({ ok: false, message: "缺少 device_id" });
    }

    let deviceId;
    try {
      deviceId = normalizeFingerprint(device_id);
    } catch {
      return res.status(400).json({ ok: false, message: "设备指纹格式无效" });
    }
    if (!verifyLicense(deviceId, license_key)) {
      return res.status(400).json({ ok: false, message: "授权码与设备指纹不匹配" });
    }

    // 检查用户是否被拉黑
    if (qq) {
      const banned = await isUserBanned(qq);
      if (banned) {
        return res.status(200).json({
          ok: false,
          message: "该用户已被拉黑，无法注册新设备",
        });
      }

      const existing = await getDevice(deviceId);
      if (existing && existing.qq && String(existing.qq) !== String(qq)) {
        return res.status(409).json({ ok: false, message: "该设备指纹已绑定其他用户" });
      }
      const count = await countUserDevices(qq);
      if (!existing && count >= MAX_DEVICES_PER_USER) {
        return res.status(200).json({
          ok: false,
          message: `设备数已达上限(${MAX_DEVICES_PER_USER})`,
        });
      }
    }

    // 注册
    await registerDevice(deviceId, {
      qq: qq || "",
      qq_name: qq_name || "",
      license_hash: sha256(String(license_key || "").replace(/\s/g, "")),
      timestamp: new Date().toISOString(),
    });

    console.log(`[register] device=${deviceId} qq=${qq}`);

    return res.status(200).json({
      ok: true,
      message: "注册成功",
      device_id: deviceId,
    });
  } catch (err) {
    console.error("register error:", err);
    return res.status(500).json({ ok: false, message: "服务器内部错误" });
  }
};
