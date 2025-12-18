const crypto = require("crypto");

const AES_ALGO = "aes-256-cbc";
const AES_KEY_LENGTH = 32;
const HMAC_KEY_LENGTH = 32;
const IV_LENGTH = 16;

function generateKeys() {
  return {
    encKey: crypto.randomBytes(AES_KEY_LENGTH),
    macKey: crypto.randomBytes(HMAC_KEY_LENGTH)
  };
}

function generateIv() {
  return crypto.randomBytes(IV_LENGTH);
}

/**
 * Encrypt-then-MAC using AES-256-CBC + HMAC-SHA256.
 * @param {Buffer} encKey
 * @param {Buffer} macKey
 * @param {Buffer} iv
 * @param {Buffer} plaintext
 * @param {Buffer} aad
 * @returns {{ciphertext: Buffer, mac: Buffer}}
 */
function encryptCbcHmac(encKey, macKey, iv, plaintext, aad) {
  const cipher = crypto.createCipheriv(AES_ALGO, encKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const h = crypto.createHmac("sha256", macKey);
  if (aad) h.update(aad);
  h.update(iv);
  h.update(ciphertext);
  const mac = h.digest();
  return { ciphertext, mac };
}

/**
 * Verify MAC in constant time and decrypt.
 * @param {Buffer} encKey
 * @param {Buffer} macKey
 * @param {Buffer} iv
 * @param {Buffer} ciphertext
 * @param {Buffer} mac
 * @param {Buffer} aad
 * @returns {Buffer} plaintext
 */
function decryptCbcHmac(encKey, macKey, iv, ciphertext, mac, aad) {
  const h = crypto.createHmac("sha256", macKey);
  if (aad) h.update(aad);
  h.update(iv);
  h.update(ciphertext);
  const expectedMac = h.digest();
  if (!crypto.timingSafeEqual(expectedMac, mac)) {
    throw new Error("MAC verification failed");
  }
  const decipher = crypto.createDecipheriv(AES_ALGO, encKey, iv);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext;
}

module.exports = {
  AES_KEY_LENGTH,
  HMAC_KEY_LENGTH,
  IV_LENGTH,
  generateKeys,
  generateIv,
  encryptCbcHmac,
  decryptCbcHmac
};


