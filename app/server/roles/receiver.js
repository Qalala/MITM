const {
  sendUi,
  logUi,
  createTcpServer,
  encodeFrame,
  decodeFrames,
  FRAME_TYPES,
  deriveKeyForAesCbcHmac,
  deriveKeyForAesGcm
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
  // Receiver uses a single decryption mode (must match sender's encryption mode)
  // Use let instead of const to allow updates
  let demo = !!config.demo;
  let encMode = Number(config.encMode || 0);
  let kxMode = config.kxMode || KX_MODES.PSK;
  let psk = config.psk ? Buffer.from(config.psk) : null;
  
  // Log the configured mode for debugging
  logUi(ws, "receiver", `Receiver configured with decryption mode: ${encMode}, KX mode: ${kxMode}`);

  let server = null;
  let conn = null;
  let running = true;

  let sessionKey = null;
  let sharedSecret = null;
  let seqIn = 0;
  let negotiatedEncMode = null; // The encryption mode negotiated with the sender
  let handshakeDone = false; // Track handshake completion

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
    handshakeDone = false;
    
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
      
      // Ensure both are numbers for proper comparison - handle both string and number types
      const senderModeNum = Number(senderEncMode);
      const receiverModeNum = Number(encMode);
      
      // Validate that conversion was successful
      if (isNaN(senderModeNum) || isNaN(receiverModeNum)) {
        const errorMsg = `Invalid encryption mode: sender=${senderEncMode}, receiver=${encMode}`;
        logUi(ws, "receiver", errorMsg);
        sendUi(ws, { type: "error", error: errorMsg });
        const err = { reason: "mode_mismatch", message: errorMsg };
        conn.write(encodeFrame(FRAME_TYPES.ERROR, Buffer.from(JSON.stringify(err))));
        conn.end();
        conn = null;
        return;
      }
      
      // Compare encryption modes
      if (senderModeNum !== receiverModeNum) {
        const errorMsg = `Encryption mode mismatch: sender uses ${senderModeNum}, receiver expects ${receiverModeNum}. Please ensure both sender and receiver use the same encryption mode.`;
        logUi(ws, "receiver", errorMsg);
        sendUi(ws, { type: "error", error: errorMsg });
        const err = { reason: "mode_mismatch", message: errorMsg };
        conn.write(encodeFrame(FRAME_TYPES.ERROR, Buffer.from(JSON.stringify(err))));
        conn.end();
        conn = null; // Allow new connection
        return;
      }
      
      // Compare key exchange modes - handle both string and enum comparisons
      const senderKxStr = String(senderKxMode).toLowerCase();
      const receiverKxStr = String(kxMode).toLowerCase();
      
      if (senderKxStr !== receiverKxStr) {
        const errorMsg = `Key exchange mode mismatch: sender uses ${senderKxMode}, receiver uses ${kxMode}`;
        logUi(ws, "receiver", errorMsg);
        sendUi(ws, { type: "error", error: errorMsg });
        const err = { reason: "mode_mismatch", message: errorMsg };
        conn.write(encodeFrame(FRAME_TYPES.ERROR, Buffer.from(JSON.stringify(err))));
        conn.end();
        conn = null; // Allow new connection
        return;
      }

      // Validate PSK for encrypted modes with PSK key exchange
      if (kxMode === KX_MODES.PSK && encMode !== ENC_MODES.PLAINTEXT) {
        if (!psk || (Buffer.isBuffer(psk) ? psk.length === 0 : String(psk).length === 0)) {
          const errorMsg = "PSK key is REQUIRED for encrypted modes. Please enter a pre-shared key.";
          logUi(ws, "receiver", errorMsg);
          sendUi(ws, { type: "error", error: errorMsg });
          const err = { reason: "psk_required", message: errorMsg };
          conn.write(encodeFrame(FRAME_TYPES.ERROR, Buffer.from(JSON.stringify(err))));
          conn.end();
          conn = null;
          return;
        }
      }

      // Use the receiver's configured decryption mode (must match sender)
      negotiatedEncMode = encMode;
      logUi(ws, "receiver", `Using decryption mode: ${negotiatedEncMode}`);

      // NEGOTIATE: confirm mode
      conn.write(encodeFrame(FRAME_TYPES.NEGOTIATE, buildNegotiate(negotiatedEncMode, kxMode)));

      // KEY_EXCHANGE from receiver
      // Store PSK in state for finalize function
      state.psk = psk;
      const { payload: kxPayload, stateUpdate } = receiverBuildKeyExchange(negotiatedEncMode, kxMode, {
        psk
      });
      Object.assign(state, stateUpdate);
      conn.write(encodeFrame(FRAME_TYPES.KEY_EXCHANGE, kxPayload));

      // Sender response (if needed)
      // For PSK mode, sender doesn't send KEY_EXCHANGE response, so we skip waiting
      let respPayload = null;
      if (kxMode !== KX_MODES.PSK) {
        // For RSA and DH modes, sender must send KEY_EXCHANGE response
        const kxResp = await frameIter.next();
        if (kxResp.done || kxResp.value.type !== FRAME_TYPES.KEY_EXCHANGE) {
          throw new Error("Expected KEY_EXCHANGE response from sender");
        }
        respPayload = kxResp.value.payload;
      }
      // For PSK mode, respPayload remains null, which is correct

      const finalizeUpdate = receiverFinalizeKeyExchange(negotiatedEncMode, kxMode, respPayload, state);
      Object.assign(state, finalizeUpdate);

      sessionKey = state.sessionKey;
      sharedSecret = state.sharedSecret;
      
      // For PSK mode with plaintext, set sessionKey from config if not already set
      if (kxMode === KX_MODES.PSK && negotiatedEncMode === ENC_MODES.PLAINTEXT && psk && !sessionKey) {
        sessionKey = psk;
      }

      conn.write(encodeFrame(FRAME_TYPES.ACK, Buffer.from(JSON.stringify({ ok: true }))));
      handshakeDone = true; // Mark handshake as complete
      logUi(ws, "receiver", "Handshake complete, ready to receive data");
      sendUi(ws, { type: "status", status: "Handshake complete - ready to receive" });
      sendUi(ws, { type: "handshakeStatus", complete: true, status: "Handshake complete - ready to receive" });

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
      handshakeDone = false;
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
        const key = sessionKey || sharedSecret;
        // Derive proper 32-byte key for AES-GCM
        const derivedKey = deriveKeyForAesGcm(key);
        const plaintext = decryptGcm(derivedKey, nonce, ct, tag, aad);
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
        // Derive proper 64-byte key for AES-CBC+HMAC (32 bytes encKey + 32 bytes macKey)
        const derivedKey = deriveKeyForAesCbcHmac(key);
        const encKey = derivedKey.slice(0, 32);
        const macKey = derivedKey.slice(32, 64);
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
    } else if (negotiatedEncMode === ENC_MODES.DIFFIE_HELLMAN) {
      try {
        // DIFFIE_HELLMAN mode uses sharedSecret as symmetric key with AES-GCM
        const key = sharedSecret || sessionKey;
        if (!key) {
          throw new Error("Shared secret not available for Diffie-Hellman decryption");
        }
        // Derive proper 32-byte key for AES-GCM
        const derivedKey = deriveKeyForAesGcm(key);
        const nonce = Buffer.from(obj.nonce, "base64");
        const ct = Buffer.from(obj.ciphertext, "base64");
        const tag = Buffer.from(obj.tag, "base64");
        const aad = Buffer.concat([Buffer.from("DATA"), seqBuf]);
        const plaintext = decryptGcm(derivedKey, nonce, ct, tag, aad);
        seqIn = obj.seq;
        const text = plaintext.toString("utf8");
        logUi(ws, "receiver", `RECV (Diffie-Hellman): ${text}`);
        sendUi(ws, { type: "log", message: `RECV: ${text}` });
        sendUi(ws, { type: "messageReceived", text });
      } catch (e) {
        logUi(ws, "receiver", `Integrity check failed (Diffie-Hellman): ${e.message}`);
        sendUi(ws, { type: "attackFailed", message: `Integrity check failed - tampering detected (Diffie-Hellman)` });
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
    handshakeDone = false;
    logUi(ws, "receiver", "Receiver stopped and sockets closed");
  }

  function updateSecurityConfig(newConfig) {
    // Update security-related config
    // Note: For receiver, changing security settings while listening may affect new connections
    const oldEncMode = encMode;
    const oldKxMode = kxMode;
    const oldPsk = psk;
    let configChanged = false;
    let changeDescription = [];
    
    if (newConfig.encMode !== undefined && newConfig.encMode !== null) {
      const newEncMode = Number(newConfig.encMode);
      if (newEncMode >= 0 && newEncMode <= 3 && newEncMode !== encMode) {
        encMode = newEncMode;
        configChanged = true;
        changeDescription.push(`decryption mode: ${oldEncMode} → ${encMode}`);
        logUi(ws, "receiver", `Security config updated: decryption mode changed from ${oldEncMode} to ${encMode}`);
      }
    }
    if (newConfig.kxMode && newConfig.kxMode !== kxMode) {
      kxMode = newConfig.kxMode;
      configChanged = true;
      changeDescription.push(`key exchange: ${oldKxMode} → ${kxMode}`);
      logUi(ws, "receiver", `Security config updated: key exchange mode changed from ${oldKxMode} to ${kxMode}`);
    }
    if (newConfig.psk !== undefined) {
      const newPsk = newConfig.psk ? Buffer.from(newConfig.psk) : null;
      const pskChanged = (newPsk && !oldPsk) || (!newPsk && oldPsk) || (newPsk && oldPsk && !newPsk.equals(oldPsk));
      if (pskChanged) {
        psk = newPsk;
        configChanged = true;
        changeDescription.push("PSK updated");
        logUi(ws, "receiver", `Security config updated: PSK ${psk ? "updated" : "cleared"}`);
      }
    }
    if (newConfig.demo !== undefined) {
      const newDemo = !!newConfig.demo;
      if (newDemo !== demo) {
        demo = newDemo;
        logUi(ws, "receiver", `Security config updated: demo mode ${demo ? "enabled" : "disabled"}`);
      }
    }
    
    // Send only ONE warning message if config changed
    if (configChanged) {
      const changeMsg = changeDescription.join(", ");
      if (conn && handshakeDone) {
        // Active connection - close it and warn once
        logUi(ws, "receiver", `⚠ Security settings changed (${changeMsg}). Closing connection.`);
        sendUi(ws, { 
          type: "log", 
          message: `⚠ Security settings changed (${changeMsg}). Connection closed. Sender must reconnect with matching encryption mode ${encMode}.` 
        });
        try {
          conn.end();
          conn.destroy();
        } catch {}
        conn = null;
        handshakeDone = false;
        sessionKey = null;
        sharedSecret = null;
        seqIn = 0;
        negotiatedEncMode = null;
      } else {
        // No active connection - just notify once
        logUi(ws, "receiver", `Security settings updated (${changeMsg}).`);
        sendUi(ws, { 
          type: "log", 
          message: `Security settings updated (${changeMsg}). New connections will use these settings.` 
        });
      }
    }
  }

  return {
    async stop() {
      cleanup();
    },
    async sendMessage() {
      // Receiver does not send chat messages in this demo.
    },
    async updateSecurityConfig(newConfig) {
      updateSecurityConfig(newConfig);
    },
    checkHandshake() {
      // For plaintext mode, handshake is complete if connection exists and handshakeDone is true
      // For encrypted modes (AES-GCM, AES-CBC+HMAC), we need sessionKey
      // For Diffie-Hellman mode, we need sharedSecret
      const isComplete = conn && handshakeDone && (
        negotiatedEncMode === ENC_MODES.PLAINTEXT || 
        (negotiatedEncMode === ENC_MODES.DIFFIE_HELLMAN && sharedSecret) ||
        (negotiatedEncMode !== ENC_MODES.DIFFIE_HELLMAN && negotiatedEncMode !== null && (sessionKey || sharedSecret))
      );
      return {
        complete: isComplete,
        status: isComplete ? "Handshake complete - encrypted" : (conn ? (handshakeDone ? "Handshake complete" : "Handshake in progress...") : "Waiting for connection...")
      };
    }
  };
}

module.exports = {
  createReceiver
};


