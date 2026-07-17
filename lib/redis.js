// lib/redis.js - Upstash Redis 连接
// 需要在 Vercel 环境变量中设置:
//   UPSTASH_REDIS_REST_URL
//   UPSTASH_REDIS_REST_TOKEN

const { Redis } = require("@upstash/redis");

let _redis = null;

function getRedis() {
  if (_redis) return _redis;

  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!url || !token) {
    throw new Error("缺少 Upstash Redis 环境变量 (UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN)");
  }

  _redis = new Redis({ url, token });
  return _redis;
}

// Key 前缀
const PREFIX = "ttfc:";

// ===== 设备授权 =====

/**
 * 注册一个设备码
 * @param {string} deviceId - 设备码 (小写)
 * @param {object} info - { qq, qq_name, license_hash, timestamp }
 */
async function registerDevice(deviceId, info) {
  const redis = getRedis();
  const key = PREFIX + "device:" + deviceId;
  await redis.hset(key, {
    device_id: deviceId,
    qq: info.qq || "",
    qq_name: info.qq_name || "",
    license_hash: info.license_hash || "",
    timestamp: info.timestamp || new Date().toISOString(),
    status: "active", // active / banned
  });
  // 加入设备集合
  await redis.sadd(PREFIX + "devices:all", deviceId);
  // 按用户分组
  if (info.qq) {
    await redis.sadd(PREFIX + "user:" + info.qq, deviceId);
  }
  return true;
}

/**
 * 查询设备状态
 * @returns {object|null} 设备信息或 null
 */
async function getDevice(deviceId) {
  const redis = getRedis();
  const key = PREFIX + "device:" + deviceId;
  const data = await redis.hgetall(key);
  if (!data || !data.device_id) return null;
  return data;
}

async function activateDevice(deviceId, tokenHash) {
  const redis = getRedis();
  const key = PREFIX + "device:" + deviceId;
  await redis.hset(key, {
    token_hash: tokenHash,
    activated_at: new Date().toISOString(),
    last_seen_at: new Date().toISOString(),
  });
}

async function touchDevice(deviceId) {
  const redis = getRedis();
  await redis.hset(PREFIX + "device:" + deviceId, {
    last_seen_at: new Date().toISOString(),
  });
}

async function saveLease(lease) {
  const redis = getRedis();
  const key = PREFIX + "lease:" + lease.lease_id;
  const ttl = Math.max(1, lease.expires_at - Math.floor(Date.now() / 1000));
  await redis.hset(key, {
    fingerprint: lease.fingerprint,
    build_id: lease.build_id,
    expires_at: String(lease.expires_at),
  });
  await redis.expire(key, ttl);
}

/**
 * 拉黑一个设备的所有设备码
 * @param {string} qq - 用户QQ
 * @param {string} reason - 拉黑原因
 */
async function banUser(qq, reason) {
  const redis = getRedis();
  const userDevices = await redis.smembers(PREFIX + "user:" + qq);

  for (const deviceId of userDevices) {
    const key = PREFIX + "device:" + deviceId;
    await redis.hset(key, { status: "banned", ban_reason: reason, ban_time: new Date().toISOString() });
  }

  await redis.hset(PREFIX + "ban:" + qq, {
    qq: qq,
    reason: reason,
    time: new Date().toISOString(),
    device_count: userDevices.length,
  });
  await redis.sadd(PREFIX + "banned:users", qq);

  return { banned_devices: userDevices.length };
}

/**
 * 解封用户
 */
async function unbanUser(qq) {
  const redis = getRedis();
  const userDevices = await redis.smembers(PREFIX + "user:" + qq);

  for (const deviceId of userDevices) {
    const key = PREFIX + "device:" + deviceId;
    await redis.hset(key, { status: "active", ban_reason: "", ban_time: "" });
  }

  await redis.del(PREFIX + "ban:" + qq);
  await redis.srem(PREFIX + "banned:users", qq);

  return { unbanned_devices: userDevices.length };
}

/**
 * 检查用户是否被拉黑
 */
async function isUserBanned(qq) {
  const redis = getRedis();
  return await redis.sismember(PREFIX + "banned:users", qq) === 1;
}

/**
 * 统计用户的设备数
 */
async function countUserDevices(qq) {
  const redis = getRedis();
  return await redis.scard(PREFIX + "user:" + qq);
}

/**
 * 获取统计数据
 */
async function getStats() {
  const redis = getRedis();
  const [totalDevices, bannedUsers] = await Promise.all([
    redis.scard(PREFIX + "devices:all"),
    redis.scard(PREFIX + "banned:users"),
  ]);

  // 获取最近 20 条记录
  const allDevices = await redis.smembers(PREFIX + "devices:all");
  const recent = [];
  for (const deviceId of allDevices.slice(-20)) {
    const info = await redis.hgetall(PREFIX + "device:" + deviceId);
    if (info && info.device_id) recent.push(info);
  }

  return {
    total_devices: totalDevices,
    banned_users: bannedUsers,
    recent: recent,
  };
}

module.exports = {
  getRedis,
  registerDevice,
  getDevice,
  activateDevice,
  touchDevice,
  saveLease,
  banUser,
  unbanUser,
  isUserBanned,
  countUserDevices,
  getStats,
};
