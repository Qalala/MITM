const { FRAME_TYPES } = require("./framing");
const { ENC_MODES, KX_MODES } = require("./constants");
const { generateKey, NONCE_LENGTH } = require("../crypto/aes_gcm");
const { generateKeys, IV_LENGTH } = require("../crypto/aes_cbc_hmac");
const { generateKeyPair, encryptWithPublicKey, decryptWithPrivateKey } = require("../crypto/rsa");
const { createDh, computeSecret } = require("../crypto/dh");

/**
 * Build a HELLO frame payload as JSON.
 */
function buildHello(role, encMode, kxMode, demoMode) {
  return Buffer.from(
    JSON.stringify({
      role,
      encMode,
      kxMode,
      demoMode: !!demoMode
    }),
    "utf8"
  );
}

/**
 * Build NEGOTIATE frame where receiver confirms/locks parameters.
 */
function buildNegotiate(encMode, kxMode) {
  return Buffer.from(
    JSON.stringify({
      encMode,
      kxMode
    }),
    "utf8"
  );
}

/**
 * Receiver-side: create key material and KEY_EXCHANGE payload based on chosen modes.
 * Returns { payload, stateUpdate }.
 */
function receiverBuildKeyExchange(encMode, kxMode, options) {
  const stateUpdate = {};
  let payloadObj = { encMode, kxMode };

  if (kxMode === KX_MODES.RSA) {
    const { publicKey, privateKey } = generateKeyPair();
    stateUpdate.rsaPrivateKey = privateKey;
    payloadObj.rsaPublicKey = publicKey;
  } else if (kxMode === KX_MODES.DH) {
    const dh = createDh();
    stateUpdate.dh = dh;
    payloadObj.dhPublicKey = dh.getPublicKey("base64");
  } else if (kxMode === KX_MODES.PSK) {
    // nothing extra; PSK provided out-of-band via config
  }

  // Session keys for symmetric encryption will be derived after KX completes.
  return {
    payload: Buffer.from(JSON.stringify(payloadObj), "utf8"),
    stateUpdate
  };
}

/**
 * Sender-side: process receiver KEY_EXCHANGE, send back encrypted session keys if needed.
 * Returns { responsePayload, stateUpdate } where responsePayload may be null (for PSK).
 */
function senderProcessKeyExchange(encMode, kxMode, keyExchangePayload, options) {
  const payloadObj = JSON.parse(keyExchangePayload.toString("utf8"));
  const stateUpdate = {};
  let responsePayload = null;

  if (kxMode === KX_MODES.RSA) {
    const sessionKey = generateKey();
    stateUpdate.sessionKey = sessionKey;
    const encryptedKey = encryptWithPublicKey(Buffer.from(payloadObj.rsaPublicKey, "utf8"), sessionKey);
    responsePayload = Buffer.from(
      JSON.stringify({
        encSessionKey: encryptedKey.toString("base64")
      }),
      "utf8"
    );
  } else if (kxMode === KX_MODES.DH) {
    const dh = createDh();
    const otherPub = Buffer.from(payloadObj.dhPublicKey, "base64");
    const secret = computeSecret(dh, otherPub);
    stateUpdate.sharedSecret = secret;
    responsePayload = Buffer.from(
      JSON.stringify({
        dhPublicKey: dh.getPublicKey("base64")
      }),
      "utf8"
    );
  } else if (kxMode === KX_MODES.PSK) {
    // PSK must be provided in options.psk (Buffer)
    // For plaintext mode, PSK is optional but if provided it should be used
    if (options && options.psk && Buffer.isBuffer(options.psk)) {
      stateUpdate.sessionKey = options.psk;
    } else if (encMode !== 0) {
      // For encrypted modes, PSK is required
      throw new Error("PSK key required");
    }
    // For plaintext mode without PSK, no sessionKey is set (which is fine)
  }

  return { responsePayload, stateUpdate };
}

/**
 * Receiver-side: finalize KX from sender response.
 */
function receiverFinalizeKeyExchange(encMode, kxMode, responsePayload, state) {
  const payloadObj = responsePayload ? JSON.parse(responsePayload.toString("utf8")) : {};
  const stateUpdate = {};

  if (kxMode === KX_MODES.RSA) {
    const encKey = Buffer.from(payloadObj.encSessionKey, "base64");
    const sessionKey = decryptWithPrivateKey(state.rsaPrivateKey, encKey);
    stateUpdate.sessionKey = sessionKey;
  } else if (kxMode === KX_MODES.DH) {
    const otherPub = Buffer.from(payloadObj.dhPublicKey, "base64");
    const secret = computeSecret(state.dh, otherPub);
    stateUpdate.sharedSecret = secret;
  } else if (kxMode === KX_MODES.PSK) {
    // PSK is shared via config - set sessionKey from state.psk if available
    // For plaintext mode, PSK might be optional, but if provided it should be set
    if (state.psk && Buffer.isBuffer(state.psk)) {
      stateUpdate.sessionKey = state.psk;
    }
  }

  return stateUpdate;
}

module.exports = {
  buildHello,
  buildNegotiate,
  receiverBuildKeyExchange,
  senderProcessKeyExchange,
  receiverFinalizeKeyExchange,
  NONCE_LENGTH,
  IV_LENGTH,
  ENC_MODES,
  KX_MODES,
  FRAME_TYPES
};


