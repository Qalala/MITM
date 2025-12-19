const {
  sendUi,
  logUi,
  createTcpServer,
  encodeFrame,
  decodeFrames,
  FRAME_TYPES
} = require("./common");
const {
  buildNegotiate,
  receiverBuildKeyExchange,
  receiverFinalizeKeyExchange,
  ENC_MODES,
  KX_MODES
} = require("../../../core/protocol/handshake");
const { encryptGcm, decryptGcm, generateNonce } = require("../../../core/crypto/aes_gcm");
const { encryptCbcHmac, decryptCbcHmac, generateIv } = require("../../../core/crypto/aes_cbc_hmac");

function createReceiver(config, ws) {
  const bindIp = "0.0.0.0";
  const port = config.port || 12347;
  const demo = !!config.demo;
  // Receiver uses a single decryption mode (must match sender's encryption mode)
  const encMode = Number(config.encMode || 0);
  const kxMode = config.kxMode || KX_MODES.PSK;
  const psk = config.psk ? Buffer.from(config.psk) : null;

  let server = null;
  let conn = null;
  let running = true;

  let sessionKey = null;
  let sharedSecret = null;
  let seqIn = 0;
  let negotiatedEncMode = null; // The encryption mode negotiated with the sender

  (async () => {
    try {
      server = await createTcpServer(bindIp, port, (c) => {
        // enforce single connection as per spec (listen(1) semantics)
        if (conn) {
          c.destroy();
          return;
        }
        conn = c;
        handleConnection().catch((e) => {
          logUi(ws, "receiver", `Connection error: ${e.message}`);
        });
      });
      logUi(ws, "receiver", `Receiver listening on ${bindIp}:${port} (TCP)`);
      sendUi(ws, { type: "status", status: `Receiver listening on ${bindIp}:${port}` });
    } catch (e) {
      logUi(ws, "receiver", `Failed to start receiver: ${e.message}`);
      sendUi(ws, { type: "error", error: e.message });
    }
  })();

  async function handleConnection() {
    // Reset state for new connection
    negotiatedEncMode = null;
    sessionKey = null;
    sharedSecret = null;
    seqIn = 0;
    
    logUi(ws, "receiver", "Client connected, starting handshake");
    const state = {};

    try {
      const frameIter = decodeFrames(conn);
      const hello = await frameIter.next();
      if (hello.done || hello.value.type !== FRAME_TYPES.HELLO) {
        throw new Error("Expected HELLO frame");
      }
      const helloPayload = JSON.parse(hello.value.payload.toString("utf8"));

      // Check if sender's encryption mode matches receiver's decryption mode
      const senderEncMode = helloPayload.encMode;
      const senderKxMode = helloPayload.kxMode;
      
      if (senderEncMode !== encMode) {
        logUi(ws, "receiver", `Encryption mode mismatch: sender uses ${senderEncMode}, receiver expects ${encMode}`);
        const err = { reason: "mode_mismatch", message: `Encryption mode mismatch: sender uses ${senderEncMode}, receiver expects ${encMode}` };
        conn.write(encodeFrame(FRAME_TYPES.ERROR, Buffer.from(JSON.stringify(err))));
        conn.end();
        conn = null; // Allow new connection
        return;
      }
      
      if (senderKxMode !== kxMode) {
        logUi(ws, "receiver", "Key exchange mode mismatch");
        const err = { reason: "mode_mismatch", message: `Key exchange mode mismatch: sender uses ${senderKxMode}, receiver uses ${kxMode}` };
        conn.write(encodeFrame(FRAME_TYPES.ERROR, Buffer.from(JSON.stringify(err))));
        conn.end();
        conn = null; // Allow new connection
        return;
      }

      // Use the receiver's configured decryption mode (must match sender)
      negotiatedEncMode = encMode;
      logUi(ws, "receiver", `Using decryption mode: ${negotiatedEncMode}`);

      // NEGOTIATE: confirm mode
      conn.write(encodeFrame(FRAME_TYPES.NEGOTIATE, buildNegotiate(negotiatedEncMode, kxMode)));

      // KEY_EXCHANGE from receiver
      const { payload: kxPayload, stateUpdate } = receiverBuildKeyExchange(negotiatedEncMode, kxMode, {
        psk
      });
      Object.assign(state, stateUpdate);
      conn.write(encodeFrame(FRAME_TYPES.KEY_EXCHANGE, kxPayload));

      // Sender response (if needed)
      const kxResp = await frameIter.next();
      let respPayload = null;
      if (!kxResp.done && kxResp.value.type === FRAME_TYPES.KEY_EXCHANGE) {
        respPayload = kxResp.value.payload;
      } else if (kxMode !== KX_MODES.PSK) {
        throw new Error("Expected KEY_EXCHANGE response");
      }

      const finalizeUpdate = receiverFinalizeKeyExchange(negotiatedEncMode, kxMode, respPayload, state);
      Object.assign(state, finalizeUpdate);

      sessionKey = state.sessionKey;
      sharedSecret = state.sharedSecret;

      conn.write(encodeFrame(FRAME_TYPES.ACK, Buffer.from(JSON.stringify({ ok: true }))));
      logUi(ws, "receiver", "Handshake complete, ready to receive data");
      sendUi(ws, { type: "status", status: "Handshake complete - encrypted" });

      // Streaming loop
      for await (const frame of frameIter) {
        if (!running) break;
        if (frame.type === FRAME_TYPES.DATA) {
          await processDataFrame(frame.payload);
        } else if (frame.type === FRAME_TYPES.CLOSE) {
          logUi(ws, "receiver", "Peer closed connection");
          break;
        } else if (frame.type === FRAME_TYPES.ERROR) {
          logUi(ws, "receiver", `Error from peer: ${frame.payload.toString("utf8")}`);
        }
      }
    } catch (e) {
      logUi(ws, "receiver", `Connection error: ${e.message}`);
      sendUi(ws, { type: "error", error: e.message });
    } finally {
      // Clean up connection but keep server running
      if (conn) {
        try {
          conn.end();
          conn.destroy();
        } catch {}
        conn = null; // Allow new connection
      }
      // Reset state for next connection
      negotiatedEncMode = null;
      sessionKey = null;
      sharedSecret = null;
      seqIn = 0;
      sendUi(ws, { type: "status", status: `Receiver listening on ${bindIp}:${port}` });
    }
  }

  async function processDataFrame(payload) {
    // payload is JSON structure depending on negotiatedEncMode.
    const obj = JSON.parse(payload.toString("utf8"));

    if (negotiatedEncMode === ENC_MODES.PLAINTEXT) {
      seqIn++;
      const text = obj.text || "";
      logUi(ws, "receiver", `RECV (plaintext): ${text}`);
      sendUi(ws, { type: "log", message: `RECV: ${text}` });
      sendUi(ws, { type: "messageReceived", text });
      // Check if message appears to be modified (contains MITM indicators)
      if (text.includes("[MITM modified]") || text.includes("HACKED") || text.toLowerCase().includes("mitm")) {
        sendUi(ws, { type: "attackSuccess", message: `Message was modified by attacker: "${text}"` });
      }
      return;
    }

    // replay protection
    if (typeof obj.seq !== "number" || obj.seq <= seqIn) {
      logUi(ws, "receiver", `Replay detected: seq ${obj.seq}`);
      sendUi(ws, { type: "attackFailed", message: `Replay attack detected and blocked (seq ${obj.seq})` });
      return;
    }
    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(BigInt(obj.seq));

    if (negotiatedEncMode === ENC_MODES.AES_GCM) {
      try {
        const nonce = Buffer.from(obj.nonce, "base64");
        const ct = Buffer.from(obj.ciphertext, "base64");
        const tag = Buffer.from(obj.tag, "base64");
        const aad = Buffer.concat([Buffer.from("DATA"), seqBuf]);
        const plaintext = decryptGcm(sessionKey, nonce, ct, tag, aad);
        seqIn = obj.seq;
        const text = plaintext.toString("utf8");
        logUi(ws, "receiver", `RECV (AES-GCM): ${text}`);
        sendUi(ws, { type: "log", message: `RECV: ${text}` });
        sendUi(ws, { type: "messageReceived", text });
      } catch (e) {
        logUi(ws, "receiver", `Integrity check failed (AES-GCM): ${e.message}`);
        sendUi(ws, { type: "attackFailed", message: `Integrity check failed - tampering detected (AES-GCM)` });
      }
    } else if (negotiatedEncMode === ENC_MODES.AES_CBC_HMAC) {
      try {
        const iv = Buffer.from(obj.iv, "base64");
        const ct = Buffer.from(obj.ciphertext, "base64");
        const mac = Buffer.from(obj.mac, "base64");
        const aad = Buffer.concat([Buffer.from("DATA"), seqBuf]);
        const key = sessionKey || sharedSecret;
        const encKey = key.slice(0, 32);
        const macKey = key.slice(32, 64);
        const plaintext = decryptCbcHmac(encKey, macKey, iv, ct, mac, aad);
        seqIn = obj.seq;
        const text = plaintext.toString("utf8");
        logUi(ws, "receiver", `RECV (AES-CBC+HMAC): ${text}`);
        sendUi(ws, { type: "log", message: `RECV: ${text}` });
        sendUi(ws, { type: "messageReceived", text });
      } catch (e) {
        logUi(ws, "receiver", `MAC verification failed (AES-CBC+HMAC): ${e.message}`);
        sendUi(ws, { type: "attackFailed", message: `MAC verification failed - tampering detected (AES-CBC+HMAC)` });
      }
    }
  }

  function cleanup() {
    running = false;
    try {
      if (conn) {
        conn.end();
        conn.destroy();
        conn = null;
      }
    } catch {}
    try {
      if (server) {
        server.close();
        server = null;
      }
    } catch {}
    // Reset state
    negotiatedEncMode = null;
    sessionKey = null;
    sharedSecret = null;
    seqIn = 0;
    logUi(ws, "receiver", "Receiver stopped and sockets closed");
  }

  return {
    async stop() {
      cleanup();
    },
    async sendMessage() {
      // Receiver does not send chat messages in this demo.
    },
    checkHandshake() {
      const isComplete = conn && sessionKey;
      return {
        complete: isComplete,
        status: isComplete ? "Handshake complete - encrypted" : (conn ? "Handshake in progress..." : "Waiting for connection...")
      };
    }
  };
}

module.exports = {
  createReceiver
};


