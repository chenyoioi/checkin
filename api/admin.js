// api/admin.js - 管理接口 (拉黑/解封/统计)

const { banUser, unbanUser, getStats } = require("../lib/redis");
const { checkRateLimit, getClientIP } = require("./_lib/ratelimit");
const { verifyOrigin } = require("../lib/security");

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

  // 速率限制: 管理接口每个 IP 每分钟最多 20 次
  const ip = getClientIP(req);
  const rl = checkRateLimit(ip, 20, 60000);
  if (!rl.allowed) {
    return res.status(429).json({ ok: false, message: "请求过于频繁" });
  }

  const adminKey = (req.body || {}).admin_key;

  if (!ADMIN_KEY) {
    return res.status(503).json({ ok: false, message: "服务端未配置管理密钥" });
  }
  if (adminKey !== ADMIN_KEY) {
    return res.status(403).json({ ok: false, message: "无权限" });
  }

  try {
    const action = (req.body || {}).action;

    if (action === "stats") {
      const stats = await getStats();
      return res.status(200).json({ ok: true, ...stats });
    }

    if (action === "ban") {
      const qq = (req.body || {}).qq;
      const reason = (req.body || {}).reason || "管理员拉黑";
      if (!qq) return res.status(400).json({ ok: false, message: "缺少 qq" });
      const result = await banUser(qq, reason);
      return res.status(200).json({ ok: true, ...result });
    }

    if (action === "unban") {
      const qq = (req.body || {}).qq;
      if (!qq) return res.status(400).json({ ok: false, message: "缺少 qq" });
      const result = await unbanUser(qq);
      return res.status(200).json({ ok: true, ...result });
    }

    return res.status(400).json({ ok: false, message: "未知 action" });
  } catch (err) {
    console.error("admin error:", err);
    return res.status(500).json({ ok: false, message: "服务器内部错误" });
  }
};
