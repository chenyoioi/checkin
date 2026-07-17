// api/verify.js - 客户端联网验证接口
//
// 客户端发送: { device_id: "xxx", license_key: "base64..." }
// 服务器返回: {
//   ok: true/false,
//   status: "active" | "banned" | "unknown",
//   message: "...",
//   signature: "RSA签名(device_id + status)"  // 防篡改
// }

const crypto = require("crypto");
const { getDevice, isUserBanned } = require("../lib/redis");
const { checkRateLimit, getClientIP } = require("./_lib/ratelimit");
const { verifyOrigin } = require("../lib/security");

// RSA 私钥 (与 AstrBot 插件使用同一把)
// 环境变量: LICENSE_PRIVATE_KEY_PEM
function getPrivateKey() {
  const pem = process.env.LICENSE_PRIVATE_KEY_PEM;
  if (!pem) throw new Error("缺少 LICENSE_PRIVATE_KEY_PEM 环境变量");
  return crypto.createPrivateKey(pem.replace(/\\n/g, "\n"));
}

// 对数据签名
function signData(data) {
  const sign = crypto.createSign("SHA256");
  sign.update(data, "utf8");
  return sign.sign(getPrivateKey(), "base64");
}

module.exports = async (req, res) => {
  if (!verifyOrigin(req)) {
    return res.status(403).json({ ok: false, message: "请求来源无效" });
  }
  if (process.env.ENABLE_LEGACY_API !== "true") {
    return res.status(410).json({ ok: false, message: "接口已升级" });
  }
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Method not allowed" });
  }

  // 速率限制: 每个 IP 每分钟最多 30 次
  const ip = getClientIP(req);
  const rl = checkRateLimit(ip, 30, 60000);
  if (!rl.allowed) {
    res.setHeader("Retry-After", Math.ceil((rl.resetTime - Date.now()) / 1000));
    return res.status(429).json({ ok: false, message: "请求过于频繁，请稍后再试" });
  }

  try {
    const { device_id, license_key } = req.body || {};

    if (!device_id) {
      return res.status(400).json({ ok: false, message: "缺少 device_id" });
    }

    const deviceId = String(device_id).trim().toLowerCase();

    // 1. 查询设备
    const device = await getDevice(deviceId);

    if (!device) {
      // 设备未注册 — 可能是未通过机器人授权
      const sig = signData(deviceId + ":unknown");
      return res.status(200).json({
        ok: false,
        status: "unknown",
        message: "设备未授权，请先获取授权码",
        signature: sig,
      });
    }

    // 2. 检查是否被拉黑
    if (device.status === "banned") {
      const sig = signData(deviceId + ":banned");
      return res.status(200).json({
        ok: false,
        status: "banned",
        message: "该设备已被拉黑",
        signature: sig,
      });
    }

    // 3. 检查关联用户是否被拉黑
    if (device.qq) {
      const userBanned = await isUserBanned(device.qq);
      if (userBanned) {
        const sig = signData(deviceId + ":banned");
        return res.status(200).json({
          ok: false,
          status: "banned",
          message: "账号已被拉黑，所有设备已失效",
          signature: sig,
        });
      }
    }

    // 4. 验证通过
    const sig = signData(deviceId + ":active");

    return res.status(200).json({
      ok: true,
      status: "active",
      message: "验证通过",
      device_id: deviceId,
      timestamp: new Date().toISOString(),
      signature: sig, // RSA 签名, 客户端可用公钥验证
    });
  } catch (err) {
    console.error("verify error:", err);
    return res.status(500).json({
      ok: false,
      status: "error",
      message: "服务器内部错误",
    });
  }
};
