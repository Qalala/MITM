const net = require("net");
const crypto = require("crypto");
const { encodeFrame, decodeFrames, FRAME_TYPES } = require("../../../core/protocol/framing");
const { log } = require("../../../core/logging/logger");

function sendUi(ws, payload) {
  try {
    ws.send(JSON.stringify(payload));
  } catch {
    // ignore
  }
}

function logUi(ws, role, message) {
  log(role, message);
  sendUi(ws, { type: "log", message: `[${role}] ${message}` });
}

function createTcpServer(bindIp, port, onConnection) {
  return new Promise((resolve, reject) => {
    const server = net.createServer(async (conn) => {
      onConnection(conn);
    });
    server.on("error", reject);
    // listen(1) as per spec: backlog of 1 to enforce single connection semantics
    server.listen(port, bindIp, 1, () => {
      resolve(server);
    });
  });
}

function createTcpClient(targetIp, port) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    socket.once("error", reject);
    socket.connect(port, targetIp, () => {
      socket.removeAllListeners("error");
      resolve(socket);
    });
  });
}

/**
 * Derive encryption key for AES-CBC+HMAC mode (needs 64 bytes: 32 for encKey + 32 for macKey)
 * Uses HKDF-like expansion: hash the input key material and expand to required length
 */
function deriveKeyForAesCbcHmac(keyMaterial) {
  if (!keyMaterial || keyMaterial.length === 0) {
    throw new Error("Key material is required for AES-CBC+HMAC");
  }
  
  // If key is already 64+ bytes, use first 64 bytes
  if (keyMaterial.length >= 64) {
    return keyMaterial.slice(0, 64);
  }
  
  // Use HKDF-like expansion: hash the key material and expand to 64 bytes
  // This ensures deterministic key derivation regardless of input key size
  const hash = crypto.createHash("sha256");
  hash.update(keyMaterial);
  const hash1 = hash.digest();
  
  // If we need more bytes, hash again with a counter
  if (hash1.length < 64) {
    const hash2 = crypto.createHash("sha256");
    hash2.update(keyMaterial);
    hash2.update(Buffer.from([0x01])); // Counter
    const hash2Digest = hash2.digest();
    return Buffer.concat([hash1, hash2Digest]).slice(0, 64);
  }
  
  return hash1.slice(0, 64);
}

/**
 * Derive encryption key for AES-GCM mode (needs 32 bytes)
 * Uses first 32 bytes of key material, or hashes if shorter
 */
function deriveKeyForAesGcm(keyMaterial) {
  if (!keyMaterial || keyMaterial.length === 0) {
    throw new Error("Key material is required for AES-GCM");
  }
  
  // If key is already 32+ bytes, use first 32 bytes
  if (keyMaterial.length >= 32) {
    return keyMaterial.slice(0, 32);
  }
  
  // Hash the key material to get exactly 32 bytes
  const hash = crypto.createHash("sha256");
  hash.update(keyMaterial);
  return hash.digest();
}

module.exports = {
  sendUi,
  logUi,
  createTcpServer,
  createTcpClient,
  encodeFrame,
  decodeFrames,
  FRAME_TYPES,
  deriveKeyForAesCbcHmac,
  deriveKeyForAesGcm
};


