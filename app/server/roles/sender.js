const {
  sendUi,
  logUi,
  createTcpClient,
  encodeFrame,
  decodeFrames,
  FRAME_TYPES,
  deriveKeyForAesCbcHmac,
  deriveKeyForAesGcm
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
  
  // Log the configured mode for debugging
  logUi(ws, "sender", `Sender configured with encryption mode: ${encMode}, KX mode: ${kxMode}`);

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

  // Removed listenForFrames - now handled inline in connect() function

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
      // Derive proper 32-byte key for AES-GCM
      const derivedKey = deriveKeyForAesGcm(key);
      const nonce = generateNonce();
      const { ciphertext, tag } = encryptGcm(derivedKey, nonce, pt, aad);
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
      // Derive proper 64-byte key for AES-CBC+HMAC (32 bytes encKey + 32 bytes macKey)
      const derivedKey = deriveKeyForAesCbcHmac(key);
      const iv = generateIv();
      const encKey = derivedKey.slice(0, 32);
      const macKey = derivedKey.slice(32, 64);
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
      // Derive proper 32-byte key for AES-GCM
      const derivedKey = deriveKeyForAesGcm(key);
      const nonce = generateNonce();
      const { ciphertext, tag } = encryptGcm(derivedKey, nonce, pt, aad);
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
    // Update config if provided - prioritize connectConfig values
    if (connectConfig) {
      if (connectConfig.targetIp) targetIp = connectConfig.targetIp;
      if (connectConfig.port) port = connectConfig.port;
      if (connectConfig.transport) transport = connectConfig.transport;
      // Always update encryption mode from connect config if provided
      if (connectConfig.encMode !== undefined && connectConfig.encMode !== null) {
        encMode = Number(connectConfig.encMode);
        logUi(ws, "sender", `Updated encryption mode to ${encMode} from connect config`);
      }
      if (connectConfig.kxMode) kxMode = connectConfig.kxMode;
      if (connectConfig.psk !== undefined) {
        psk = connectConfig.psk ? Buffer.from(connectConfig.psk) : null;
      }
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
    
    // Log the actual values being used for connection
    logUi(ws, "sender", `Connecting with encryption mode: ${connectEncMode}, KX mode: ${connectKxMode}`);
    
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
      
      // Ensure proper comparison - convert to numbers for encMode, strings for kxMode
      const negoEncMode = Number(nego.encMode);
      const negoKxMode = String(nego.kxMode).toLowerCase();
      const connectKxModeStr = String(connectKxMode).toLowerCase();
      
      if (negoEncMode !== connectEncMode || negoKxMode !== connectKxModeStr) {
        throw new Error(`Receiver refused parameters (downgrade prevention): sender encMode=${connectEncMode}, receiver encMode=${negoEncMode}, sender kxMode=${connectKxMode}, receiver kxMode=${nego.kxMode}`);
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

      // Wait for ACK from receiver
      const ack = await frameIter.next();
      if (ack.done || ack.value.type !== FRAME_TYPES.ACK) {
        throw new Error("Expected ACK after key exchange");
      }
      
      handshakeDone = true;
      logUi(ws, "sender", "Handshake complete, ready to send data");
      
      // Send handshake status update - this is critical for client to know handshake is complete
      // Send handshakeStatus FIRST, then status
      sendUi(ws, { type: "handshakeStatus", complete: true, status: "Handshake complete - ready to send" });
      sendUi(ws, { type: "status", status: "Handshake complete - ready to send" });
      
      // Start listening for incoming frames (DATA, ERROR, etc.) in the background
      // Use the same frameIter to continue reading from the socket
      (async () => {
        try {
          for await (const frame of frameIter) {
            if (!running) break;
            if (frame.type === FRAME_TYPES.DATA) {
              logUi(ws, "sender", `DATA from receiver: ${frame.payload.toString("utf8")}`);
            } else if (frame.type === FRAME_TYPES.ERROR) {
              logUi(ws, "sender", `Error from receiver: ${frame.payload.toString("utf8")}`);
            } else if (frame.type === FRAME_TYPES.CLOSE) {
              logUi(ws, "sender", "Receiver closed connection");
              break;
            }
          }
        } catch (e) {
          if (running) {
            logUi(ws, "sender", `Background receive error: ${e.message}`);
          }
        }
      })();
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
      
      // Verify handshake is complete - check both socket and handshakeDone flag
      if (!socket) {
        sendUi(ws, { type: "error", error: "Not connected. Please connect first." });
        return;
      }
      
      if (!handshakeDone) {
        sendUi(ws, { type: "error", error: "Handshake not complete. Wait for connection..." });
        // Also send current handshake status
        const currentEncMode = storedConfig.encMode !== undefined ? storedConfig.encMode : encMode;
        const isComplete = socket && handshakeDone && (
          currentEncMode === ENC_MODES.PLAINTEXT || 
          (currentEncMode === ENC_MODES.DIFFIE_HELLMAN && sharedSecret) ||
          (currentEncMode !== ENC_MODES.DIFFIE_HELLMAN && (sessionKey || sharedSecret))
        );
        sendUi(ws, { 
          type: "handshakeStatus", 
          complete: isComplete, 
          status: isComplete ? "Handshake complete - connection established" : (socket ? (handshakeDone ? "Handshake complete" : "Handshake in progress...") : "Not connected")
        });
        return;
      }
      
      // Verify we have the necessary keys for encrypted modes
      const currentEncMode = storedConfig.encMode !== undefined ? storedConfig.encMode : encMode;
      if (currentEncMode !== ENC_MODES.PLAINTEXT) {
        const key = sessionKey || sharedSecret;
        if (!key || key.length === 0) {
          const keyType = currentEncMode === ENC_MODES.DIFFIE_HELLMAN ? "shared secret" : "session key";
          sendUi(ws, { type: "error", error: `${keyType} not available. Handshake may have failed.` });
          return;
        }
        
        // Validate key size for AES-CBC+HMAC (needs at least some material to derive from)
        if (currentEncMode === ENC_MODES.AES_CBC_HMAC && key.length === 0) {
          sendUi(ws, { type: "error", error: "Key material too short for AES-CBC+HMAC mode." });
          return;
        }
      }
      
      try {
        const payload = buildDataPayload(text, currentEncMode);
        socket.write(encodeFrame(FRAME_TYPES.DATA, payload));
        logUi(ws, "sender", `SENT: ${text}`);
        sendUi(ws, { type: "messageSent", text });
      } catch (e) {
        logUi(ws, "sender", `Failed to send message: ${e.message}`);
        sendUi(ws, { type: "error", error: `Failed to send message: ${e.message}` });
      }
    },
    checkHandshake() {
      // Use the current encryption mode (may have been updated during connect)
      const currentEncMode = storedConfig.encMode !== undefined ? storedConfig.encMode : encMode;
      
      // For plaintext mode, handshake is complete if connection exists and handshakeDone is true
      // For encrypted modes (AES-GCM, AES-CBC+HMAC), we need sessionKey
      // For Diffie-Hellman mode, we need sharedSecret
      const isComplete = socket && handshakeDone && (
        currentEncMode === ENC_MODES.PLAINTEXT || 
        (currentEncMode === ENC_MODES.DIFFIE_HELLMAN && sharedSecret) ||
        (currentEncMode !== ENC_MODES.DIFFIE_HELLMAN && (sessionKey || sharedSecret))
      );
      return {
        complete: isComplete,
        status: isComplete ? "Handshake complete - connection established" : (socket ? (handshakeDone ? "Handshake complete" : "Handshake in progress...") : "Not connected")
      };
    }
  };
}

module.exports = {
  createSender
};


