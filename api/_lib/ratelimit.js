/**
 * api/_lib/ratelimit.js - 简易速率限制
 *
 * Vercel serverless 无状态, 这只是基础防护。
 * 主要 DDoS 防护由 Cloudflare 完成 (代理模式 + 速率限制规则)。
 * 这层防止单个 IP 高频刷接口。
 */

// 内存存储 (每个 serverless 实例独立, 粗粒度限流)
const store = new Map();

// 清理过期记录 (每 5 分钟)
const CLEANUP_INTERVAL = 5 * 60 * 1000;
let lastCleanup = Date.now();

function cleanup() {
  const now = Date.now();
  if (now - lastCleanup < CLEANUP_INTERVAL) return;
  lastCleanup = now;
  for (const [key, entry] of store) {
    if (now > entry.resetTime) {
      store.delete(key);
    }
  }
}

/**
 * 检查速率限制
 * @param {string} ip - 客户端 IP
 * @param {number} maxRequests - 窗口内最大请求数
 * @param {number} windowMs - 时间窗口 (毫秒)
 * @returns {object} { allowed: boolean, remaining: number, resetTime: number }
 */
function checkRateLimit(ip, maxRequests = 30, windowMs = 60000) {
  cleanup();

  const now = Date.now();
  const key = ip;

  let entry = store.get(key);
  if (!entry || now > entry.resetTime) {
    entry = {
      count: 1,
      resetTime: now + windowMs,
    };
    store.set(key, entry);
    return { allowed: true, remaining: maxRequests - 1, resetTime: entry.resetTime };
  }

  entry.count++;
  if (entry.count > maxRequests) {
    return { allowed: false, remaining: 0, resetTime: entry.resetTime };
  }

  return { allowed: true, remaining: maxRequests - entry.count, resetTime: entry.resetTime };
}

/**
 * 获取客户端真实 IP (穿透 Cloudflare)
 */
function getClientIP(req) {
  return (
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

module.exports = { checkRateLimit, getClientIP };
