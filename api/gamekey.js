// api/gamekey.js - 游戏关键值下发接口
//
// 客户端发送: { device_id, license_key }
// 服务器返回: {
//   ok: true,
//   game_key: "aesKeyBase64",       ← 32字节 AES 密钥 (base64)
//   salt: "encMagicBase64",          ← 4字节 XOR加密的物理校准常量 (base64)
//   expires: "...",
//   signature: "RSA签名"
// }
//
// Java 层 (LicenseBridge.smali) 提取 game_key 和 salt, 拼接为 "game_key:salt"
// 实际传递给 C# 的格式: "aesKeyBase64:encMagicBase64"
//
// C# 层解析:
//   1. 按 ':' 分割 → aesKeyBase64, encMagicBase64
//   2. Base64 解码 → 32字节 AES密钥, 4字节 加密常量
//   3. XOR(encMagic[i], aesKey[i]) for i in 0..3 → 4字节明文
//   4. BitConverter.ToSingle → 物理校准常量 (正确值 = 1.337f)
//   5. 没有 game_key → 解出 0f → 赛车不动 / 物理错误

const crypto = require("crypto");
const { getDevice, isUserBanned } = require("../lib/redis");
const { checkRateLimit, getClientIP } = require("./_lib/ratelimit");
const { verifyOrigin } = require("../lib/security");

// 服务器主密钥 (环境变量, 永远不进入 APK)
const SERVER_SECRET = process.env.SERVER_SECRET || "ttfc_server_secret_2026_DO_NOT_LEAK";

// 物理校准常量: 游戏运行必需的正确值
// 被加密后发给客户端, 客户端用 game_key 解密
// 1.337f 不是整数也不是常见数值, 攻击者很难猜到
// 如果解出的值不是 1.337f, 游戏物理计算完全错误
const MAGIC_PHYSICS_VALUE = 1.337;

// RSA 私钥
function getPrivateKey() {
  const pem = process.env.LICENSE_PRIVATE_KEY_PEM;
  if (!pem) throw new Error("缺少 LICENSE_PRIVATE_KEY_PEM");
  return crypto.createPrivateKey(pem.replace(/\\n/g, "\n"));
}

function signData(data) {
  const sign = crypto.createSign("SHA256");
  sign.update(data, "utf8");
  return sign.sign(getPrivateKey(), "base64");
}

// 派生当天的 game_key (每天不同)
function deriveGameKey(deviceId, dateStr) {
  const hmac = crypto.createHmac("sha256", SERVER_SECRET);
  hmac.update(deviceId + ":" + dateStr);
  return hmac.digest(); // 32 bytes Buffer
}

// XOR 加密物理校准常量
// 用 AES key 的前 4 字节 XOR 物理常量的 4 字节
// 客户端用同样的 XOR 解密
function encryptMagicValue(aesKey) {
  // 1.337f → 4 字节 (小端 IEEE 754)
  const magicBuf = Buffer.alloc(4);
  magicBuf.writeFloatLE(MAGIC_PHYSICS_VALUE);

  // XOR: 魔法值 ^ AES key 前 4 字节
  const encBuf = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) {
    encBuf[i] = magicBuf[i] ^ aesKey[i];
  }

  return encBuf.toString("base64");
}

module.exports = async (req, res) => {
  if (!verifyOrigin(req)) {
    return res.status(403).json({ ok: false, message: "请求来源无效" });
  }
  if (process.env.ENABLE_LEGACY_API !== "true") {
    return res.status(410).json({ ok: false, message: "接口已升级" });
  }
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false });

  // 速率限制
  const ip = getClientIP(req);
  const rl = checkRateLimit(ip, 20, 60000);
  if (!rl.allowed) {
    res.setHeader("Retry-After", Math.ceil((rl.resetTime - Date.now()) / 1000));
    return res.status(429).json({ ok: false, message: "请求过于频繁" });
  }

  try {
    const { device_id, license_key } = req.body || {};
    if (!device_id) return res.status(400).json({ ok: false, message: "缺少 device_id" });

    const deviceId = String(device_id).trim().toLowerCase();

    // 1. 查设备
    const device = await getDevice(deviceId);
    if (!device) {
      return res.status(200).json({ ok: false, status: "unknown", message: "设备未注册" });
    }

    // 2. 检查拉黑
    if (device.status === "banned") {
      return res.status(200).json({ ok: false, status: "banned", message: "设备已拉黑" });
    }
    if (device.qq) {
      const banned = await isUserBanned(device.qq);
      if (banned) return res.status(200).json({ ok: false, status: "banned", message: "账号已拉黑" });
    }

    // 3. 派生 game_key (当天有效)
    const now = new Date();
    const dateStr = now.toISOString().slice(0, 10);
    const gameKeyRaw = deriveGameKey(deviceId, dateStr);

    // 4. 生成 AES 密钥 (32 字节)
    const saltHex = crypto.randomBytes(16).toString("hex");
    const aesKey = crypto.createHash("sha256").update(gameKeyRaw.toString("hex") + saltHex).digest();

    // 5. 加密物理校准常量 (核心防破解)
    //    用 AES key 的前 4 字节 XOR 加密 1.337f
    //    客户端需要正确的 game_key 才能解出 1.337f
    //    没有 game_key → 解出 0f 或垃圾值 → 赛车物理完全错误
    const encMagic = encryptMagicValue(aesKey);

    // 6. 过期时间
    const tomorrow = new Date(now);
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);

    // 7. RSA 签名 (防篡改)
    const signPayload = deviceId + ":" + aesKey.toString("hex") + ":" + saltHex;
    const signature = signData(signPayload);

    // 注意: encMagic 放在 salt 字段里, Java 层会自动拼接为 "game_key:salt"
    // C# 层按 ':' 分割即可解析, 不需要改 smali 代码
    console.log(`[gamekey] device=${deviceId} date=${dateStr} magic=encrypted`);

    return res.status(200).json({
      ok: true,
      status: "active",
      game_key: aesKey.toString("base64"),   // AES 密钥 (base64, 44 字符)
      salt: encMagic,                         // 加密的物理常量 (base64, 8 字符)
      date: dateStr,
      expires: tomorrow.toISOString(),
      signature: signature,
    });
  } catch (err) {
    console.error("gamekey error:", err);
    return res.status(500).json({ ok: false, message: "服务器错误" });
  }
};
