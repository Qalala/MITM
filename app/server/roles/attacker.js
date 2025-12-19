const net = require("net");
const {
  sendUi,
  logUi,
  encodeFrame,
  decodeFrames,
  FRAME_TYPES
} = require("./common");

function createAttacker(config, ws) {
  const listenIp = "0.0.0.0";
  const listenPort = config.port || 12347;
  let targetIp = config.targetIp || "127.0.0.1";
  let targetPort = config.port || 12347;
  let activeAttackType = null; // Current active attack: "modify", "drop", "delay", "replay", "downgrade", or null
  let dropRate = Number(config.dropRate || 10);
  let delayMs = Number(config.delayMs || 1000);
  let modifyText = (config.modifyText && config.modifyText.trim()) || "[MITM modified]";

  let server = null;
  let clientConn = null;
  let serverConn = null;
  let running = true;
  let lastFrameFromSender = null;

  (async () => {
    try {
      server = net.createServer((c) => {
        // If there's an existing connection, close it first
        if (clientConn) {
          try {
            clientConn.end();
            clientConn.destroy();
          } catch {}
        }
        if (serverConn) {
          try {
            serverConn.end();
            serverConn.destroy();
          } catch {}
        }
        clientConn = c;
        handleNewClient().catch((e) =>
          logUi(ws, "attacker", `Client handling error: ${e.message}`)
        );
      });
      server.listen(listenPort, listenIp, () => {
        logUi(ws, "attacker", `Attacker listening on ${listenIp}:${listenPort}`);
        sendUi(ws, {
          type: "status",
          status: `Attacker listening, forwarding to ${targetIp}:${targetPort}`
        });
      });
    } catch (e) {
      logUi(ws, "attacker", `Attacker failed to start: ${e.message}`);
      sendUi(ws, { type: "error", error: e.message });
    }
  })();

  async function handleNewClient() {
    // Clean up previous connections if any
    if (clientConn && clientConn !== server.connections?.[0]) {
      try {
        clientConn.end();
        clientConn.destroy();
      } catch {}
    }
    if (serverConn) {
      try {
        serverConn.end();
        serverConn.destroy();
      } catch {}
    }
    
    if (!targetIp || targetIp === "127.0.0.1") {
      logUi(ws, "attacker", "ERROR: Target IP not configured. Please set Target IP to receiver's IP address.");
      sendUi(ws, { type: "error", error: "Target IP not configured. Please set Target IP in Network Setup." });
      try {
        if (clientConn) {
          clientConn.end();
          clientConn.destroy();
        }
      } catch {}
      clientConn = null;
      return;
    }
    
    logUi(ws, "attacker", `Sender connected to attacker, connecting to real receiver at ${targetIp}:${targetPort}`);
    serverConn = new net.Socket();
    
    try {
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error("Connection timeout"));
        }, 10000); // 10 second timeout
        
        serverConn.once("error", (err) => {
          clearTimeout(timeout);
          reject(err);
        });
        serverConn.once("connect", () => {
          clearTimeout(timeout);
          serverConn.removeAllListeners("error");
          resolve();
        });
        serverConn.connect(targetPort, targetIp);
      });
      logUi(ws, "attacker", "Connected to real receiver, starting bidirectional relay");
      sendUi(ws, { type: "status", status: `MITM active: sender <-> attacker <-> receiver (${targetIp}:${targetPort})` });

      relay(clientConn, serverConn, "sender->receiver").catch((e) =>
        logUi(ws, "attacker", `Relay error (s->r): ${e.message}`)
      );
      relay(serverConn, clientConn, "receiver->sender").catch((e) =>
        logUi(ws, "attacker", `Relay error (r->s): ${e.message}`)
      );
    } catch (e) {
      logUi(ws, "attacker", `Failed to connect to receiver at ${targetIp}:${targetPort}: ${e.message}`);
      sendUi(ws, { type: "error", error: `Failed to connect to receiver: ${e.message}. Check that receiver is running and Target IP is correct.` });
      try {
        if (clientConn) {
          clientConn.end();
          clientConn.destroy();
        }
        if (serverConn) {
          serverConn.end();
          serverConn.destroy();
        }
      } catch {}
      clientConn = null;
      serverConn = null;
    }
  }

  async function relay(src, dst, direction) {
    const fromSender = direction === "sender->receiver";
    const fromReceiver = direction === "receiver->sender";
    const frameIter = decodeFrames(src);
    for await (const frame of frameIter) {
      if (!running) break;
      const rawHex = frame.payload.toString("hex");
      const rawB64 = frame.payload.toString("base64");
      logUi(
        ws,
        "attacker",
        `${direction} frame type=${frame.type} len=${frame.payload.length} raw-hex=${rawHex.slice(
          0,
          64
        )}...`
      );
      
      // Detect attack failures from receiver responses
      if (fromReceiver && frame.type === FRAME_TYPES.ERROR) {
        try {
          const errorObj = JSON.parse(frame.payload.toString("utf8"));
          if (errorObj.reason === "mode_mismatch" || errorObj.reason) {
            sendUi(ws, { type: "attackFailed", message: `Attack failed: ${errorObj.reason || "receiver rejected"}` });
          }
        } catch {}
      }

      // Attack logic - only applies if an attack is active
      let outFrame = frame;
      
      // Store last DATA frame from sender for replay attacks
      if (fromSender && frame.type === FRAME_TYPES.DATA) {
        lastFrameFromSender = frame;
      }
      
      // Apply active attack (only if one is triggered)
      if (activeAttackType === "drop") {
        if (maybe(dropRate)) {
          logUi(ws, "attacker", `Dropping ${direction} frame per dropRate (${dropRate}%)`);
          sendUi(ws, { type: "attackSuccess", message: `Dropped ${direction} frame (${dropRate}% chance)` });
          continue; // Don't forward this frame
        }
      }
      
      if (activeAttackType === "delay" && delayMs > 0) {
        logUi(ws, "attacker", `Delaying ${direction} frame by ${delayMs}ms`);
        sendUi(ws, { type: "attackSuccess", message: `Delayed ${direction} frame by ${delayMs}ms` });
        await new Promise((r) => setTimeout(r, delayMs));
      }
      
      // Modify attack - only works on plaintext DATA frames
      if (activeAttackType === "modify" && frame.type === FRAME_TYPES.DATA) {
        try {
          const payloadStr = frame.payload.toString("utf8");
          const obj = JSON.parse(payloadStr);
          if (typeof obj.text === "string") {
            // This is plaintext - we can modify it
            const originalText = obj.text;
            obj.text = modifyText;
            const newPayload = Buffer.from(JSON.stringify(obj), "utf8");
            outFrame = { ...frame, payload: newPayload };
            logUi(ws, "attacker", `Modified ${direction} plaintext DATA: "${originalText}" -> "${modifyText}"`);
            sendUi(ws, { type: "attackSuccess", message: `Modified ${direction} message: "${originalText}" -> "${modifyText}"` });
          } else {
            // Encrypted payload - cannot modify
            logUi(ws, "attacker", `Modify attack: ${direction} frame is encrypted, cannot modify`);
            sendUi(ws, { type: "attackFailed", message: `Modify attack failed on ${direction}: message is encrypted (cannot modify ciphertext)` });
          }
        } catch (e) {
          // If we can't parse as JSON, it's likely encrypted
          logUi(ws, "attacker", `Modify attack: failed to parse ${direction} payload (likely encrypted): ${e.message}`);
          sendUi(ws, { type: "attackFailed", message: `Modify attack failed on ${direction}: cannot parse encrypted payload` });
        }
      }
      
      // Replay attack - only works on sender->receiver DATA frames
      if (activeAttackType === "replay" && fromSender && frame.type === FRAME_TYPES.DATA && lastFrameFromSender) {
        // Replay the last DATA frame instead of the current one
        logUi(ws, "attacker", "Replaying last DATA frame from sender");
        outFrame = lastFrameFromSender;
        sendUi(ws, { type: "attackSuccess", message: "Replaying last DATA frame from sender" });
      }
      
      // Downgrade attack - only works on HELLO frames from sender
      if (activeAttackType === "downgrade" && fromSender && frame.type === FRAME_TYPES.HELLO) {
        try {
          const hello = JSON.parse(frame.payload.toString("utf8"));
          const originalMode = hello.encMode;
          hello.encMode = 0; // force plaintext
          const newPayload = Buffer.from(JSON.stringify(hello), "utf8");
          outFrame = { ...frame, payload: newPayload };
          logUi(ws, "attacker", `Attempted downgrade from mode ${originalMode} to plaintext (mode 0) in HELLO`);
          sendUi(ws, { type: "attackSuccess", message: `Attempted downgrade attack: mode ${originalMode} -> 0` });
          // Note: We'll detect failure when receiver sends ERROR frame
        } catch (e) {
          logUi(ws, "attacker", `Downgrade attack: failed to parse HELLO: ${e.message}`);
          sendUi(ws, { type: "attackFailed", message: "Downgrade attack failed: cannot parse HELLO" });
        }
      }

      // Forward
      const encoded = encodeFrame(outFrame.type, outFrame.payload);
      dst.write(encoded);
    }
  }

  function maybe(percent) {
    return Math.random() * 100 < percent;
  }

  function cleanup() {
    running = false;
    try {
      if (clientConn) {
        clientConn.end();
        clientConn.destroy();
        clientConn = null;
      }
    } catch {}
    try {
      if (serverConn) {
        serverConn.end();
        serverConn.destroy();
        serverConn = null;
      }
    } catch {}
    try {
      if (server) {
        server.close();
        server = null;
      }
    } catch {}
    logUi(ws, "attacker", "Attacker stopped and sockets closed");
  }

  function triggerAttack(attackType, attackConfig) {
    activeAttackType = attackType;
    if (attackConfig) {
      if (attackConfig.dropRate !== undefined) {
        dropRate = Number(attackConfig.dropRate || 10);
      }
      if (attackConfig.delayMs !== undefined) {
        delayMs = Number(attackConfig.delayMs || 1000);
      }
      if (attackConfig.modifyText !== undefined) {
        modifyText = (attackConfig.modifyText && attackConfig.modifyText.trim()) || "[MITM modified]";
      }
    }
    logUi(ws, "attacker", `Attack triggered: ${attackType}`);
    sendUi(ws, { type: "status", status: `Attack active: ${attackType}` });
    sendUi(ws, { type: "attackStatus", message: `Attack active: ${attackType}`, success: true });
  }
  
  function stopAttack() {
    activeAttackType = null;
    logUi(ws, "attacker", "All attacks stopped");
    sendUi(ws, { type: "status", status: "All attacks stopped - passive relay mode" });
    sendUi(ws, { type: "attackStatus", message: "All attacks stopped - passive relay mode", success: true });
  }

  return {
    async stop() {
      cleanup();
    },
    async sendMessage() {
      // Attacker does not send its own chat; it only relays.
    },
    checkHandshake() {
      const isComplete = clientConn && serverConn;
      return {
        complete: isComplete,
        status: isComplete ? "MITM relay active - connections established" : (clientConn || serverConn ? "Partial connection..." : "Waiting for connections...")
      };
    },
    triggerAttack,
    stopAttack
  };
}

module.exports = {
  createAttacker
};


