const {
  sendUi,
  logUi,
  createTcpClient,
  encodeFrame,
  decodeFrames,
  FRAME_TYPES
} = require("./common");
const {
  buildHello,
  ENC_MODES,
  KX_MODES,
  senderProcessKeyExchange
} = require("../../../core/protocol/handshake");
const { encryptGcm, generateNonce } = require("../../../core/crypto/aes_gcm");
const { encryptCbcHmac, generateIv } = require("../../../core/crypto/aes_cbc_hmac");

function createSender(config, ws) {
  let targetIp = config.targetIp || "127.0.0.1";
  let port = config.port || 12347;
  let transport = config.transport || "tcp";
  let demo = !!config.demo;
  let encMode = Number(config.encMode || 0);
  let kxMode = config.kxMode || KX_MODES.PSK;
  let psk = config.psk ? Buffer.from(config.psk) : null;

  let socket = null;
  let running = true;
  let handshakeDone = false;

  let sessionKey = null;
  let sharedSecret = null;
  let seqOut = 0;
  
  // Store config for later connection
  let storedConfig = { targetIp, port, transport, encMode, kxMode, psk, demo };

  async function doHandshake() {
    const hello = buildHello("sender", encMode, kxMode, demo);
    socket.write(encodeFrame(FRAME_TYPES.HELLO, hello));

    const frameIter = decodeFrames(socket);
    const negotiate = await frameIter.next();
    if (negotiate.done || negotiate.value.type !== FRAME_TYPES.NEGOTIATE) {
      throw new Error("Expected NEGOTIATE frame");
    }
    const nego = JSON.parse(negotiate.value.payload.toString("utf8"));
    if (nego.encMode !== encMode || nego.kxMode !== kxMode) {
      throw new Error("Receiver refused parameters (downgrade prevention)");
    }

    const kx = await frameIter.next();
    if (kx.done || kx.value.type !== FRAME_TYPES.KEY_EXCHANGE) {
      throw new Error("Expected KEY_EXCHANGE from receiver");
    }

    const { responsePayload, stateUpdate } = senderProcessKeyExchange(
      encMode,
      kxMode,
      kx.value.payload,
      { psk }
    );
    if (responsePayload) {
      socket.write(encodeFrame(FRAME_TYPES.KEY_EXCHANGE, responsePayload));
    }
      sessionKey = stateUpdate.sessionKey;
      sharedSecret = stateUpdate.sharedSecret;
      
      // For PSK mode with plaintext, ensure sessionKey is set from PSK if provided
      if (connectKxMode === KX_MODES.PSK && connectEncMode === ENC_MODES.PLAINTEXT && connectPsk && !sessionKey) {
        sessionKey = connectPsk;
      }

      const ack = await frameIter.next();
    if (ack.done || ack.value.type !== FRAME_TYPES.ACK) {
      throw new Error("Expected ACK after key exchange");
    }
    handshakeDone = true;
    logUi(ws, "sender", "Handshake complete, ready to send data");
    sendUi(ws, { type: "status", status: "Handshake complete - encrypted" });
  }

  async function listenForFrames() {
    const frameIter = decodeFrames(socket);
    for await (const frame of frameIter) {
      if (!running) break;
      if (frame.type === FRAME_TYPES.ERROR) {
        logUi(ws, "sender", `Error from receiver: ${frame.payload.toString("utf8")}`);
      } else if (frame.type === FRAME_TYPES.DATA) {
        logUi(ws, "sender", `DATA from receiver: ${frame.payload.toString("utf8")}`);
      }
    }
    cleanup();
  }

  function buildDataPayload(text, useEncMode = encMode) {
    if (useEncMode === ENC_MODES.PLAINTEXT) {
      return Buffer.from(JSON.stringify({ text }), "utf8");
    }

    const seq = ++seqOut;
    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(BigInt(seq));
    const aad = Buffer.concat([Buffer.from("DATA"), seqBuf]);
    const key = sessionKey || sharedSecret;
    const pt = Buffer.from(text, "utf8");

    if (useEncMode === ENC_MODES.AES_GCM) {
      const nonce = generateNonce();
      const { ciphertext, tag } = encryptGcm(key, nonce, pt, aad);
      return Buffer.from(
        JSON.stringify({
          seq,
          nonce: nonce.toString("base64"),
          ciphertext: ciphertext.toString("base64"),
          tag: tag.toString("base64")
        }),
        "utf8"
      );
    }

    if (useEncMode === ENC_MODES.AES_CBC_HMAC) {
      const iv = generateIv();
      const encKey = key.slice(0, 32);
      const macKey = key.slice(32, 64);
      const { ciphertext, mac } = encryptCbcHmac(encKey, macKey, iv, pt, aad);
      return Buffer.from(
        JSON.stringify({
          seq,
          iv: iv.toString("base64"),
          ciphertext: ciphertext.toString("base64"),
          mac: mac.toString("base64")
        }),
        "utf8"
      );
    }

    if (useEncMode === ENC_MODES.DIFFIE_HELLMAN) {
      // DIFFIE_HELLMAN mode uses sharedSecret as symmetric key with AES-GCM
      if (!key) {
        throw new Error("Shared secret not available for Diffie-Hellman encryption");
      }
      const nonce = generateNonce();
      const { ciphertext, tag } = encryptGcm(key, nonce, pt, aad);
      return Buffer.from(
        JSON.stringify({
          seq,
          nonce: nonce.toString("base64"),
          ciphertext: ciphertext.toString("base64"),
          tag: tag.toString("base64")
        }),
        "utf8"
      );
    }

    return Buffer.from(JSON.stringify({ text }), "utf8");
  }

  function cleanup() {
    running = false;
    try {
      if (socket) {
        socket.end();
        socket.destroy();
        socket = null;
      }
    } catch {}
    logUi(ws, "sender", "Sender stopped and socket closed");
  }

  async function connect(connectConfig) {
    // Update config if provided
    if (connectConfig) {
      if (connectConfig.targetIp) targetIp = connectConfig.targetIp;
      if (connectConfig.port) port = connectConfig.port;
      if (connectConfig.transport) transport = connectConfig.transport;
      if (connectConfig.encMode !== undefined) encMode = Number(connectConfig.encMode);
      if (connectConfig.kxMode) kxMode = connectConfig.kxMode;
      if (connectConfig.psk) psk = Buffer.from(connectConfig.psk);
      if (connectConfig.demo !== undefined) demo = !!connectConfig.demo;
      
      // Update stored config
      storedConfig = { targetIp, port, transport, encMode, kxMode, psk, demo };
    }
    
    const connectTargetIp = targetIp;
    const connectPort = port;
    const connectTransport = transport;
    const connectEncMode = encMode;
    const connectKxMode = kxMode;
    const connectPsk = psk;
    const connectDemo = demo;
    
    // Clean up existing connection if any
    if (socket) {
      try {
        socket.end();
        socket.destroy();
      } catch {}
      socket = null;
    }
    
    // Reset state for new connection
    handshakeDone = false;
    sessionKey = null;
    sharedSecret = null;
    seqOut = 0;
    running = true;
    
    if (connectTransport === "udp-broadcast") {
      logUi(
        ws,
        "sender",
        "UDP broadcast mode is handled by separate script (optional demo); TCP sender active."
      );
      return;
    }
    
    try {
      socket = await createTcpClient(connectTargetIp, connectPort);
      logUi(ws, "sender", `Connected to ${connectTargetIp}:${connectPort}, starting handshake`);
      
      // Use connect config for handshake
      const hello = buildHello("sender", connectEncMode, connectKxMode, connectDemo);
      socket.write(encodeFrame(FRAME_TYPES.HELLO, hello));

      const frameIter = decodeFrames(socket);
      const negotiate = await frameIter.next();
      if (negotiate.done || negotiate.value.type !== FRAME_TYPES.NEGOTIATE) {
        throw new Error("Expected NEGOTIATE frame");
      }
      const nego = JSON.parse(negotiate.value.payload.toString("utf8"));
      if (nego.encMode !== connectEncMode || nego.kxMode !== connectKxMode) {
        throw new Error("Receiver refused parameters (downgrade prevention)");
      }

      const kx = await frameIter.next();
      if (kx.done || kx.value.type !== FRAME_TYPES.KEY_EXCHANGE) {
        throw new Error("Expected KEY_EXCHANGE from receiver");
      }

      // Ensure PSK is passed correctly (as Buffer or string)
      const pskForHandshake = connectPsk ? (Buffer.isBuffer(connectPsk) ? connectPsk : Buffer.from(connectPsk)) : null;
      const { responsePayload, stateUpdate } = senderProcessKeyExchange(
        connectEncMode,
        connectKxMode,
        kx.value.payload,
        { psk: pskForHandshake }
      );
      if (responsePayload) {
        socket.write(encodeFrame(FRAME_TYPES.KEY_EXCHANGE, responsePayload));
      }
      sessionKey = stateUpdate.sessionKey;
      sharedSecret = stateUpdate.sharedSecret;
      
      // For PSK mode with plaintext, ensure sessionKey is set from PSK if provided
      if (connectKxMode === KX_MODES.PSK && connectEncMode === ENC_MODES.PLAINTEXT && connectPsk && !sessionKey) {
        sessionKey = connectPsk;
      }

      const ack = await frameIter.next();
      if (ack.done || ack.value.type !== FRAME_TYPES.ACK) {
        throw new Error("Expected ACK after key exchange");
      }
      handshakeDone = true;
      logUi(ws, "sender", "Handshake complete, ready to send data");
      sendUi(ws, { type: "status", status: "Handshake complete - encrypted" });
      
      listenForFrames().catch((e) =>
        logUi(ws, "sender", `Background receive error: ${e.message}`)
      );
    } catch (e) {
      logUi(ws, "sender", `Failed to connect: ${e.message}`);
      sendUi(ws, { type: "error", error: e.message });
      // Don't call cleanup() on connection errors - allow retry
      // Just reset handshake state
      handshakeDone = false;
      sessionKey = null;
      sharedSecret = null;
      seqOut = 0;
      // Close socket if it exists, but don't destroy the entire sender instance
      if (socket) {
        try {
          socket.end();
          socket.destroy();
        } catch {}
        socket = null;
      }
    }
  }

  return {
    async stop() {
      cleanup();
    },
    async connect(cfg) {
      await connect(cfg);
    },
    async sendMessage(text) {
      // Check current transport from stored config
      const currentTransport = storedConfig.transport || transport;
      if (currentTransport === "udp-broadcast") {
        sendUi(ws, {
          type: "error",
          error: "UDP broadcast sending is available via scripts/udp_broadcast_demo.js"
        });
        return;
      }
      if (!socket || !handshakeDone) {
        sendUi(ws, { type: "error", error: "Handshake not complete. Wait for connection..." });
        return;
      }
      const payload = buildDataPayload(text);
      socket.write(encodeFrame(FRAME_TYPES.DATA, payload));
      logUi(ws, "sender", `SENT: ${text}`);
      sendUi(ws, { type: "messageSent", text });
    },
    checkHandshake() {
      // For plaintext mode, handshake is complete if connection exists and handshakeDone is true
      // For encrypted modes (AES-GCM, AES-CBC+HMAC), we need sessionKey
      // For Diffie-Hellman mode, we need sharedSecret
      const isComplete = socket && handshakeDone && (
        encMode === ENC_MODES.PLAINTEXT || 
        (encMode === ENC_MODES.DIFFIE_HELLMAN && sharedSecret) ||
        (encMode !== ENC_MODES.DIFFIE_HELLMAN && (sessionKey || sharedSecret))
      );
      return {
        complete: isComplete,
        status: isComplete ? "Handshake complete - encrypted" : (socket ? (handshakeDone ? "Handshake complete" : "Handshake in progress...") : "Not connected")
      };
    }
  };
}

module.exports = {
  createSender
};


