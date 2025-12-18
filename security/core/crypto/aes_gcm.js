const crypto = require("crypto");

const ALGO = "aes-256-gcm";
const KEY_LENGTH = 32; // 256-bit
const NONCE_LENGTH = 12; // GCM standard

function generateKey() {
  return crypto.randomBytes(KEY_LENGTH);
}

function generateNonce() {
  return crypto.randomBytes(NONCE_LENGTH);
}

/**
 * Encrypt with AES-256-GCM.
 * @param {Buffer} key
 * @param {Buffer} nonce
 * @param {Buffer} plaintext
 * @param {Buffer} aad
 * @returns {{ciphertext: Buffer, tag: Buffer}}
 */
function encryptGcm(key, nonce, plaintext, aad) {
  const cipher = crypto.createCipheriv(ALGO, key, nonce);
  if (aad) {
    cipher.setAAD(aad);
  }
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, tag };
}

/**
 * Decrypt with AES-256-GCM.
 * @param {Buffer} key
 * @param {Buffer} nonce
 * @param {Buffer} ciphertext
 * @param {Buffer} tag
 * @param {Buffer} aad
 * @returns {Buffer} plaintext
 */
function decryptGcm(key, nonce, ciphertext, tag, aad) {
  const decipher = crypto.createDecipheriv(ALGO, key, nonce);
  if (aad) {
    decipher.setAAD(aad);
  }
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext;
}

module.exports = {
  KEY_LENGTH,
  NONCE_LENGTH,
  generateKey,
  generateNonce,
  encryptGcm,
  decryptGcm
};


