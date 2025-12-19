const net = require("net");
const {
  sendUi,
  logUi,
  encodeFrame,
  decodeFrames,
  FRAME_TYPES
} = require("./common");
const { ENC_MODES } = require("../../../core/protocol/constants");

function createAttacker(config, ws) {
  const listenIp = "0.0.0.0";
  const listenPort = config.port || 12347;
  let targetIp = config.targetIp || null; // No default, must be set
  let targetPort = config.port || 12347;
  let mode = config.attackMode || "passive";
  let dropRate = Number(config.dropRate || 0);
  let delayMs = Number(config.delayMs || 0);
  let modifyText = (config.modifyText && config.modifyText.trim()) || "[MITM modified]";
  
  let attackActive = false;

  let server = null;
  let clientConn = null;
  let serverConn = null;
  let running = true;
  let lastFrameFromSender = null;
  let lastFrameFromReceiver = null;
  let negotiatedEncMode = null; // Track encryption mode from handshake

  // Attack log helper
  function logAttack(message, level = "info") {
    logUi(ws, "attacker", message);
    sendUi(ws, { type: "attackLog", message, level });
  }

  // Extract plaintext from DATA frame if possible
  function extractPlaintext(frame) {
    if (frame.type !== FRAME_TYPES.DATA) {
      return null;
    }
    
    try {
      const payloadStr = frame.payload.toString("utf8");
      const obj = JSON.parse(payloadStr);
      if (typeof obj.text === "string") {
        return obj.text;
      }
    } catch (e) {
      // Not plaintext JSON, likely encrypted
    }
    return null;
  }

  let isHandlingClient = false; // Prevent concurrent client handling

  (async () => {
    try {
      server = net.createServer((c) => {
        // If there's an existing connection, close it first
        if (clientConn) {
          try {
            clientConn.end();
            clientConn.destroy();
          } catch {}
          clientConn = null;
        }
        if (serverConn) {
          try {
            serverConn.end();
            serverConn.destroy();
          } catch {}
          serverConn = null;
        }
        
        // Prevent concurrent handling
        if (isHandlingClient) {
          logUi(ws, "attacker", "New connection rejected: already handling a connection");
          try {
            c.end();
            c.destroy();
          } catch {}
          return;
        }
        
        clientConn = c;
        isHandlingClient = true;
        handleNewClient().catch((e) => {
          logUi(ws, "attacker", `Client handling error: ${e.message}`);
        }).finally(() => {
          isHandlingClient = false;
        });
      });
      // Use backlog=1 to enforce single connection semantics (like receiver)
      server.listen(listenPort, listenIp, 1, () => {
        logUi(ws, "attacker", `Attacker listening on ${listenIp}:${listenPort}`);
        sendUi(ws, {
          type: "status",
          status: `Attacker listening on ${listenIp}:${listenPort}. Configure targets and click 'Start Attack' to begin.`
        });
      });
      server.on("error", (err) => {
        logUi(ws, "attacker", `Server error: ${err.message}`);
        sendUi(ws, { type: "error", error: `Server error: ${err.message}` });
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
    
    // Use targetIp as the victim's IP (receiver that attacker proxies to)
    const actualTargetIp = targetIp;
    
    if (!actualTargetIp) {
      logUi(ws, "attacker", "ERROR: Victim IP (target IP) not configured. Please enter victim's IP address.");
      sendUi(ws, { type: "error", error: "Victim IP (target IP) not configured. Please enter the victim's IP address in Target IP field." });
      try {
        if (clientConn) {
          clientConn.end();
          clientConn.destroy();
        }
      } catch {}
      clientConn = null;
      isHandlingClient = false;
      return;
    }
    
    logAttack(`Sender connected to attacker, connecting to real receiver at ${actualTargetIp}:${targetPort}`, "info");
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
        serverConn.connect(targetPort, actualTargetIp);
      });
      logAttack("Connected to real receiver, starting bidirectional relay", "info");
      sendUi(ws, { type: "status", status: `MITM active: sender <-> attacker <-> receiver (${actualTargetIp}:${targetPort})` });

      // Add error and close handlers to detect connection failures
      const cleanupConnections = () => {
        if (clientConn) {
          try {
            clientConn.removeAllListeners();
            clientConn.end();
            clientConn.destroy();
          } catch {}
          clientConn = null;
        }
        if (serverConn) {
          try {
            serverConn.removeAllListeners();
            serverConn.end();
            serverConn.destroy();
          } catch {}
          serverConn = null;
        }
        isHandlingClient = false;
      };

      const onClientError = (err) => {
        logAttack(`Sender connection error: ${err.message}`, "failed");
        cleanupConnections();
      };
      const onClientClose = () => {
        logAttack("Sender connection closed", "warning");
        cleanupConnections();
      };
      const onServerError = (err) => {
        logAttack(`Receiver connection error: ${err.message}`, "failed");
        cleanupConnections();
      };
      const onServerClose = () => {
        logAttack("Receiver connection closed", "warning");
        cleanupConnections();
      };

      clientConn.on("error", onClientError);
      clientConn.on("close", onClientClose);
      serverConn.on("error", onServerError);
      serverConn.on("close", onServerClose);

      // Start bidirectional relay with proper cleanup
      const relayPromise1 = relay(clientConn, serverConn, "sender->receiver").catch((e) => {
        logUi(ws, "attacker", `Relay error (s->r): ${e.message}`);
      }).finally(() => {
        // When one relay stops, cleanup the other
        cleanupConnections();
      });
      
      const relayPromise2 = relay(serverConn, clientConn, "receiver->sender").catch((e) => {
        logUi(ws, "attacker", `Relay error (r->s): ${e.message}`);
      }).finally(() => {
        // When one relay stops, cleanup the other
        cleanupConnections();
      });
    } catch (e) {
      logAttack(`Failed to connect to receiver at ${actualTargetIp}:${targetPort}: ${e.message}`, "failed");
      sendUi(ws, { type: "error", error: `Failed to connect to receiver: ${e.message}. Check that receiver is running and Receiver IP is correct.` });
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
      isHandlingClient = false;
    }
  }

  async function relay(src, dst, direction) {
    const fromSender = direction === "sender->receiver";
    const fromReceiver = direction === "receiver->sender";
    const frameIter = decodeFrames(src);
    
    for await (const frame of frameIter) {
      if (!running) break;
      
      // Extract encryption mode from HELLO frame
      if (frame.type === FRAME_TYPES.HELLO) {
        try {
          const hello = JSON.parse(frame.payload.toString("utf8"));
          negotiatedEncMode = hello.encMode;
          logAttack(`Detected encryption mode: ${negotiatedEncMode} (${negotiatedEncMode === ENC_MODES.PLAINTEXT ? "Plaintext" : "Encrypted"})`, "info");
        } catch (e) {
          // Ignore parse errors
        }
      }
      
      // For passive mode, try to extract and display plaintext
      if (mode === "passive" && frame.type === FRAME_TYPES.DATA) {
        const plaintext = extractPlaintext(frame);
        if (plaintext !== null) {
          logAttack(`[PASSIVE] Plaintext message: "${plaintext}"`, "success");
        } else {
          logAttack(`[PASSIVE] Encrypted message (cannot decrypt)`, "warning");
        }
      }
      
      const rawHex = frame.payload.toString("hex");
      logUi(
        ws,
        "attacker",
        `${direction} frame type=${frame.type} len=${frame.payload.length} raw-hex=${rawHex.slice(0, 64)}...`
      );
      
      // Detect attack failures from receiver responses
      if (fromReceiver && frame.type === FRAME_TYPES.ERROR) {
        try {
          const errorObj = JSON.parse(frame.payload.toString("utf8"));
          const reason = errorObj.reason || "unknown";
          const message = errorObj.message || "receiver rejected";
          logAttack(`Attack blocked: ${reason} - ${message}`, "failed");
          sendUi(ws, { type: "attackFailed", message: `Attack failed: ${reason} - ${message}` });
        } catch (e) {
          logAttack(`Attack failed: receiver sent error frame`, "failed");
          sendUi(ws, { type: "attackFailed", message: "Attack failed: receiver rejected connection" });
        }
      }

      // Attack logic
      let outFrame = frame;
      if (fromSender) {
        // Store last frame for replay
        if (frame.type === FRAME_TYPES.DATA) {
          lastFrameFromSender = frame;
        }
        
        // Apply attack modes
        if (mode === "drop") {
          if (maybe(dropRate)) {
            logAttack(`Dropping frame per dropRate (${dropRate}%)`, "warning");
            continue; // Don't forward this frame
          }
        }
        
        if (mode === "delay" && delayMs > 0) {
          logAttack(`Delaying frame by ${delayMs}ms`, "info");
          await new Promise((r) => setTimeout(r, delayMs));
        }
        
        if (mode === "modify" && frame.type === FRAME_TYPES.DATA) {
          try {
            const plaintext = extractPlaintext(frame);
            if (plaintext !== null) {
              // This is plaintext - we can modify it
              const obj = JSON.parse(frame.payload.toString("utf8"));
              obj.text = modifyText;
              const newPayload = Buffer.from(JSON.stringify(obj), "utf8");
              outFrame = { ...frame, payload: newPayload };
              logAttack(`Modified plaintext DATA frame: "${modifyText}"`, "success");
              sendUi(ws, { type: "attackSuccess", message: `Successfully modified plaintext message to: "${modifyText}"` });
            } else {
              // Encrypted payload - cannot modify
              logAttack("Modify attack failed: message is encrypted (cannot modify ciphertext)", "failed");
              sendUi(ws, { type: "attackFailed", message: "Modify attack failed: message is encrypted (cannot modify ciphertext without decryption key)" });
            }
          } catch (e) {
            // If we can't parse as JSON, it's likely encrypted
            logAttack(`Modify attack failed: cannot parse payload (likely encrypted): ${e.message}`, "failed");
            sendUi(ws, { type: "attackFailed", message: "Modify attack failed: cannot parse encrypted payload" });
          }
        }
        
        if (mode === "replay" && frame.type === FRAME_TYPES.DATA && lastFrameFromSender) {
          // Replay the last DATA frame instead of the current one
          logAttack("Replaying last DATA frame", "warning");
          outFrame = lastFrameFromSender;
          sendUi(ws, { type: "attackSuccess", message: "Replaying last DATA frame" });
          // Note: This will likely fail if encryption mode has replay protection
        }
        
        if (mode === "downgrade" && frame.type === FRAME_TYPES.HELLO) {
          try {
            const hello = JSON.parse(frame.payload.toString("utf8"));
            const originalMode = hello.encMode;
            hello.encMode = 0; // force plaintext
            const newPayload = Buffer.from(JSON.stringify(hello), "utf8");
            outFrame = { ...frame, payload: newPayload };
            logAttack(`Attempted downgrade from mode ${originalMode} to plaintext (mode 0) in HELLO`, "warning");
            sendUi(ws, { type: "attackSuccess", message: `Attempted downgrade attack: mode ${originalMode} -> 0` });
            // Note: We'll detect failure when receiver sends ERROR frame
          } catch (e) {
            logAttack(`Downgrade attack failed: cannot parse HELLO: ${e.message}`, "failed");
            sendUi(ws, { type: "attackFailed", message: "Downgrade attack failed: cannot parse HELLO" });
          }
        }
      }

      // Forward - check connection state before writing
      if (!dst || dst.destroyed || dst.closed) {
        logAttack(`Destination connection closed, stopping relay: ${direction}`, "warning");
        break;
      }
      
      try {
        const encoded = encodeFrame(outFrame.type, outFrame.payload);
        // Check if socket is writable before writing
        if (!dst.writable) {
          logAttack(`Destination socket not writable, stopping relay: ${direction}`, "warning");
          break;
        }
        const written = dst.write(encoded);
        // Handle backpressure (though unlikely with our frame sizes)
        if (!written) {
          await new Promise((resolve) => dst.once("drain", resolve));
        }
      } catch (e) {
        logAttack(`Failed to write frame in ${direction}: ${e.message}`, "failed");
        break; // Exit relay loop on write error
      }
    }
    
    // Relay loop exited - log reason
    logAttack(`Relay stopped: ${direction}`, "info");
  }

  function maybe(percent) {
    return Math.random() * 100 < percent;
  }

  function updateAttackConfig(newConfig) {
    if (newConfig.attackMode !== undefined) {
      mode = newConfig.attackMode;
      logAttack(`Attack mode updated to: ${mode}`, "info");
    }
    if (newConfig.dropRate !== undefined) {
      dropRate = Number(newConfig.dropRate);
    }
    if (newConfig.delayMs !== undefined) {
      delayMs = Number(newConfig.delayMs);
    }
    if (newConfig.modifyText !== undefined) {
      modifyText = (newConfig.modifyText && newConfig.modifyText.trim()) || "[MITM modified]";
    }
    // Update target IP (victim's IP - the receiver that attacker proxies to)
    if (newConfig.targetIp !== undefined) {
      targetIp = newConfig.targetIp || null;
      if (targetIp) {
        logAttack(`Victim IP updated to: ${targetIp}`, "info");
      }
    }
  }

  async function startAttack(attackConfig) {
    attackActive = true;
    // Update target IP from config (victim's IP - the receiver that attacker proxies to)
    if (attackConfig.targetIp) {
      targetIp = attackConfig.targetIp;
    }
    
    updateAttackConfig(attackConfig);
    
    if (!targetIp) {
      logAttack("ERROR: Victim IP (target IP) is required. Please enter victim's IP address.", "failed");
      sendUi(ws, { type: "error", error: "Victim IP is required. Please enter the target IP address." });
      attackActive = false;
      return;
    }
    
    logAttack(`Attack started: mode=${mode}, victim=${targetIp}:${targetPort}`, "info");
    sendUi(ws, { type: "status", status: `Attack active: ${mode} mode, victim: ${targetIp}:${targetPort}` });
    
    // The attacker listens and intercepts when sender connects
    if (!server) {
      logAttack("Attacker server not ready. Please wait for server to start.", "warning");
      return;
    }
    
    logAttack("Attacker is ready. Waiting for sender to connect...", "info");
    logAttack(`Note: Sender should connect to attacker's IP (shown in Local IP), not victim's IP (${targetIp})`, "info");
    logAttack(`Attacker will intercept sender connections and proxy to victim at ${targetIp}:${targetPort}`, "info");
  }

  function cleanup() {
    running = false;
    attackActive = false;
    isHandlingClient = false;
    try {
      if (clientConn) {
        clientConn.removeAllListeners();
        clientConn.end();
        clientConn.destroy();
        clientConn = null;
      }
    } catch {}
    try {
      if (serverConn) {
        serverConn.removeAllListeners();
        serverConn.end();
        serverConn.destroy();
        serverConn = null;
      }
    } catch {}
    try {
      if (server) {
        server.removeAllListeners();
        server.close();
        server = null;
      }
    } catch {}
    logUi(ws, "attacker", "Attacker stopped and sockets closed");
  }

  return {
    async stop() {
      cleanup();
    },
    async sendMessage() {
      // Attacker does not send its own chat; it only relays.
    },
    async startAttack(config) {
      await startAttack(config);
    },
    async updateAttackConfig(newConfig) {
      updateAttackConfig(newConfig);
    },
    async updateSecurityConfig(newConfig) {
      // Attacker doesn't use security config, but implement for consistency
      updateAttackConfig(newConfig);
    },
    checkHandshake() {
      const isComplete = clientConn && serverConn;
      return {
        complete: isComplete,
        status: isComplete ? "MITM relay active - connections established" : (clientConn || serverConn ? "Partial connection..." : attackActive ? "Attack active, waiting for connections..." : "Waiting for connections...")
      };
    }
  };
}

module.exports = {
  createAttacker
};
