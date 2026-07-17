const crypto = require("crypto");

const SESSION_VERSION = "2";
const DEFAULT_SESSION_TTL_SECONDS = 15 * 24 * 60 * 60;

function decodePem(value, name) {
  if (!value) throw new Error(`缺少 ${name} 环境变量`);
  return value.replace(/\|/g, "\n").replace(/\\n/g, "\n").trim() + "\n";
}

function getPrivateKey() {
  return crypto.createPrivateKey(decodePem(process.env.LICENSE_PRIVATE_KEY_PEM, "LICENSE_PRIVATE_KEY_PEM"));
}

function getPublicKey() {
  if (process.env.LICENSE_PUBLIC_KEY_PEM) {
    return crypto.createPublicKey(decodePem(process.env.LICENSE_PUBLIC_KEY_PEM, "LICENSE_PUBLIC_KEY_PEM"));
  }
  return crypto.createPublicKey(getPrivateKey());
}

function base64url(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizeFingerprint(value) {
  const fingerprint = String(value || "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) {
    throw new Error("INVALID_FINGERPRINT");
  }
  return fingerprint;
}

function normalizeBuildId(value) {
  const buildId = String(value || "").trim();
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(buildId)) {
    throw new Error("INVALID_BUILD_ID");
  }
  return buildId;
}

function normalizeNonce(value) {
  const nonce = String(value || "").trim();
  if (!/^[A-Za-z0-9_-]{22,128}$/.test(nonce)) {
    throw new Error("INVALID_NONCE");
  }
  return nonce;
}

function verifyLicense(fingerprint, licenseKey) {
  try {
    const signature = Buffer.from(String(licenseKey || "").replace(/\s/g, ""), "base64");
    if (signature.length < 128) return false;
    return crypto.verify(
      "RSA-SHA256",
      Buffer.from(fingerprint, "utf8"),
      getPublicKey(),
      signature
    );
  } catch {
    return false;
  }
}

function safeEqualHex(left, right) {
  if (!/^[a-f0-9]{64}$/i.test(left || "") || !/^[a-f0-9]{64}$/i.test(right || "")) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function getBuildConfig(buildId) {
  let configs;
  try {
    configs = JSON.parse(process.env.GAME_CONFIGS_JSON || "{}");
  } catch {
    throw new Error("GAME_CONFIGS_JSON 不是有效 JSON");
  }
  const encoded = configs[buildId];
  if (typeof encoded !== "string" || !/^[A-Za-z0-9+/=]+$/.test(encoded)) {
    throw new Error("BUILD_NOT_ALLOWED");
  }
  const config = Buffer.from(encoded, "base64");
  if (config.length < 8 || config.length > 4096 || config.subarray(0, 4).toString("ascii") !== "TCV2") {
    throw new Error("INVALID_BUILD_CONFIG");
  }
  return config;
}

function deriveKey(rootKey, leaseId, purpose) {
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    rootKey,
    Buffer.from(leaseId, "hex"),
    Buffer.from(`ttfc-v2:${purpose}`, "utf8"),
    32
  ));
}

function canonicalSession(fields) {
  return [
    fields.version,
    fields.lease_id,
    fields.build_id,
    fields.fingerprint,
    fields.nonce,
    String(fields.issued_at),
    String(fields.expires_at),
    fields.iv,
    fields.ciphertext,
    fields.unlock_key,
    fields.mac,
  ].join("|");
}

function createSessionEnvelope({ fingerprint, buildId, nonce, config, ttlSeconds }) {
  const now = Math.floor(Date.now() / 1000);
  const ttl = Number(ttlSeconds || process.env.SESSION_TTL_SECONDS || DEFAULT_SESSION_TTL_SECONDS);
  if (!Number.isInteger(ttl) || ttl < 60 || ttl > 30 * 24 * 60 * 60) throw new Error("INVALID_SESSION_TTL");

  const rootKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const leaseId = crypto.randomBytes(16).toString("hex");
  const encryptionKey = deriveKey(rootKey, leaseId, "encryption");
  const macKey = deriveKey(rootKey, leaseId, "authentication");
  const cipher = crypto.createCipheriv("aes-256-cbc", encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(config), cipher.final()]);

  const fields = {
    version: SESSION_VERSION,
    lease_id: leaseId,
    build_id: buildId,
    fingerprint,
    nonce,
    issued_at: now,
    expires_at: now + ttl,
    iv: base64url(iv),
    ciphertext: base64url(ciphertext),
    unlock_key: base64url(rootKey),
  };
  const macPayload = canonicalSession({ ...fields, mac: "" }).slice(0, -1);
  fields.mac = base64url(crypto.createHmac("sha256", macKey).update(macPayload).digest());
  fields.signature = base64url(crypto.sign("RSA-SHA256", Buffer.from(canonicalSession(fields)), getPrivateKey()));
  return fields;
}

function verifyOrigin(req) {
  const expected = process.env.CF_ORIGIN_SECRET;
  if (!expected) return process.env.NODE_ENV !== "production";
  const supplied = String(req.headers["x-ttfc-origin"] || "");
  const left = Buffer.from(expected);
  const right = Buffer.from(supplied);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

module.exports = {
  base64url,
  canonicalSession,
  createSessionEnvelope,
  getBuildConfig,
  normalizeBuildId,
  normalizeFingerprint,
  normalizeNonce,
  safeEqualHex,
  sha256,
  verifyLicense,
  verifyOrigin,
};
