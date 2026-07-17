const assert = require("node:assert/strict");
const crypto = require("crypto");
const test = require("node:test");

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
process.env.LICENSE_PRIVATE_KEY_PEM = privateKey.export({ type: "pkcs8", format: "pem" });
process.env.LICENSE_PUBLIC_KEY_PEM = publicKey.export({ type: "spki", format: "pem" });

const {
  canonicalSession,
  createSessionEnvelope,
  getBuildConfig,
  normalizeFingerprint,
  verifyLicense,
} = require("../lib/security");

test("build config is selected by the exact build id", () => {
  const config = Buffer.concat([Buffer.from("TCV2"), Buffer.from([2, 0, 0, 0])]);
  process.env.GAME_CONFIGS_JSON = JSON.stringify({ release_a: config.toString("base64") });
  assert.deepEqual(getBuildConfig("release_a"), config);
  assert.throws(() => getBuildConfig("release_b"), /BUILD_NOT_ALLOWED/);
});

function derive(root, leaseId, purpose) {
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    root,
    Buffer.from(leaseId, "hex"),
    Buffer.from(`ttfc-v2:${purpose}`),
    32
  ));
}

test("license is bound to the normalized Android fingerprint", () => {
  const fingerprint = "ab".repeat(32);
  const license = crypto.sign("RSA-SHA256", Buffer.from(fingerprint), privateKey).toString("base64");
  assert.equal(verifyLicense(fingerprint, license), true);
  assert.equal(verifyLicense("cd".repeat(32), license), false);
  assert.equal(normalizeFingerprint(fingerprint.toUpperCase()), fingerprint);
});

test("session envelope is signed, authenticated, and decryptable", () => {
  const config = Buffer.concat([
    Buffer.from("TCV2"),
    Buffer.from([2, 0, 0, 0]),
  ]);
  const session = createSessionEnvelope({
    fingerprint: "12".repeat(32),
    buildId: "android-release-1",
    nonce: "A".repeat(22),
    config,
    ttlSeconds: 300,
  });

  assert.equal(crypto.verify(
    "RSA-SHA256",
    Buffer.from(canonicalSession(session)),
    publicKey,
    Buffer.from(session.signature, "base64url")
  ), true);

  const root = Buffer.from(session.unlock_key, "base64url");
  const macKey = derive(root, session.lease_id, "authentication");
  const macPayload = canonicalSession({ ...session, mac: "" }).slice(0, -1);
  const expectedMac = crypto.createHmac("sha256", macKey).update(macPayload).digest();
  assert.equal(crypto.timingSafeEqual(expectedMac, Buffer.from(session.mac, "base64url")), true);

  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    derive(root, session.lease_id, "encryption"),
    Buffer.from(session.iv, "base64url")
  );
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(session.ciphertext, "base64url")),
    decipher.final(),
  ]);
  assert.deepEqual(plaintext, config);
});

test("changing a signed field invalidates the signature", () => {
  const session = createSessionEnvelope({
    fingerprint: "34".repeat(32),
    buildId: "android-release-1",
    nonce: "B".repeat(22),
    config: Buffer.concat([Buffer.from("TCV2"), Buffer.from([2, 0, 0, 0])]),
    ttlSeconds: 300,
  });
  session.build_id = "tampered";
  assert.equal(crypto.verify(
    "RSA-SHA256",
    Buffer.from(canonicalSession(session)),
    publicKey,
    Buffer.from(session.signature, "base64url")
  ), false);
});

test("default lease lifetime is fifteen days", () => {
  delete process.env.SESSION_TTL_SECONDS;
  const session = createSessionEnvelope({
    fingerprint: "56".repeat(32),
    buildId: "android-release-1",
    nonce: "C".repeat(22),
    config: Buffer.concat([Buffer.from("TCV2"), Buffer.from([2, 0, 0, 0])]),
  });
  assert.equal(session.expires_at - session.issued_at, 15 * 24 * 60 * 60);
});
