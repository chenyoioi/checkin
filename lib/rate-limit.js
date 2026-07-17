const { getRedis } = require("./redis");

async function checkDistributedRateLimit(scope, identity, limit, windowSeconds) {
  const redis = getRedis();
  const bucket = Math.floor(Date.now() / (windowSeconds * 1000));
  const key = `ttfc:rl:${scope}:${identity}:${bucket}`;
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, windowSeconds + 5);
  return { allowed: count <= limit, remaining: Math.max(0, limit - count) };
}

function clientIp(req) {
  return String(
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    "unknown"
  ).slice(0, 128);
}

module.exports = { checkDistributedRateLimit, clientIp };
