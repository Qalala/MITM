const { test } = require("node:test");
const assert = require("assert");
const {
  generateKey,
  generateNonce,
  encryptGcm,
  decryptGcm
} = require("../core/crypto/aes_gcm");
const {
  generateKeys,
  generateIv,
  encryptCbcHmac,
  decryptCbcHmac
} = require("../core/crypto/aes_cbc_hmac");

test("AES-GCM roundtrip and tamper detection", () => {
  const key = generateKey();
  const nonce = generateNonce();
  const aad = Buffer.from("AAD", "utf8");
  const pt = Buffer.from("secret message", "utf8");
  const { ciphertext, tag } = encryptGcm(key, nonce, pt, aad);
  const decrypted = decryptGcm(key, nonce, ciphertext, tag, aad);
  assert.strictEqual(decrypted.toString("utf8"), "secret message");

  // tamper
  const tampered = Buffer.from(ciphertext);
  tampered[0] ^= 0xff;
  assert.throws(() => decryptGcm(key, nonce, tampered, tag, aad));
});

test("AES-CBC+HMAC roundtrip and tamper detection", () => {
  const { encKey, macKey } = generateKeys();
  const iv = generateIv();
  const aad = Buffer.from("AAD", "utf8");
  const pt = Buffer.from("cbc secret", "utf8");
  const { ciphertext, mac } = encryptCbcHmac(encKey, macKey, iv, pt, aad);
  const decrypted = decryptCbcHmac(encKey, macKey, iv, ciphertext, mac, aad);
  assert.strictEqual(decrypted.toString("utf8"), "cbc secret");

  const tampered = Buffer.from(ciphertext);
  tampered[0] ^= 0xff;
  assert.throws(() => decryptCbcHmac(encKey, macKey, iv, tampered, mac, aad));
});


