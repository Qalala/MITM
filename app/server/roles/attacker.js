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
  // MITM Proxy Mode:
  // Attacker listens on all interfaces (0.0.0.0) like receiver
  // Sender connects to attacker's IP, attacker intercepts and forwards to receiver
  // This is application-layer MITM - attacker is in the middle of all communication
  const listenIp = "0.0.0.0"; // Always listen on all interfaces (like receiver)
  const listenPort = config.port || 12347;
  let targetIp = config.targetIp || null; // Receiver's IP (victim) - where to forward intercepted traffic
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
  let senderFrameBuffer = []; // Buffer frames from sender until receiver connection is ready
  let receiverReady = false; // Track if receiver connection is established

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
      // Attacker always listens on 0.0.0.0 (all interfaces) - works on any machine
      server.listen(listenPort, listenIp, 1, () => {
        if (targetIp) {
          logAttack(`[MITM] Attacker listening on ${listenIp}:${listenPort} (stealth mode - not discoverable)`, "success");
          logAttack(`[MITM] Sender should connect to attacker's IP (shown in Local IP)`, "info");
          logAttack(`[MITM] Attacker will intercept and forward to receiver at ${targetIp}:${targetPort}`, "info");
          logAttack(`[MITM] Attacker is invisible to discovery - sender/receiver cannot detect attacker`, "info");
          sendUi(ws, {
            type: "status",
            status: `MITM Active: Listening on ${listenIp}:${listenPort}. Sender connects to attacker's IP, attacker intercepts and forwards to receiver (${targetIp}:${targetPort}).`
          });
        } else {
          logAttack(`[MITM] Attacker listening on ${listenIp}:${listenPort} (stealth mode)`, "info");
          logAttack(`[MITM] Configure receiver's IP in Target IP field to enable interception`, "warning");
          sendUi(ws, {
            type: "status",
            status: `Attacker listening on ${listenIp}:${listenPort}. Configure receiver's IP to enable interception.`
          });
        }
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
    
    // Reset state for new connection
    senderFrameBuffer = [];
    receiverReady = false;
    
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
    
    // Forward to receiver's actual IP address
    // Attacker and receiver are on different machines (normal case)
    const forwardIp = actualTargetIp;
    
    logAttack(`Sender connected to attacker, connecting to real receiver at ${forwardIp}:${targetPort}`, "info");
    logAttack(`[MITM] Attacker is in the middle: Sender -> Attacker -> Receiver`, "success");
    
    // Start buffering frames from sender immediately (before receiver connection is ready)
    const senderRelayPromise = (async () => {
      try {
        const frameIter = decodeFrames(clientConn);
        for await (const frame of frameIter) {
          if (!running || !clientConn) break;
          
          // If receiver is not ready, buffer the frame
          if (!receiverReady) {
            senderFrameBuffer.push(frame);
            logAttack(`[MITM] Buffering frame from sender (receiver not ready yet)`, "info");
            continue;
          }
          
          // Receiver is ready, process frame normally
          await processAndForwardFrame(frame, clientConn, serverConn, "sender->receiver");
        }
      } catch (e) {
        if (running && clientConn) {
          logAttack(`Sender relay error: ${e.message}`, "failed");
        }
      }
    })();
    
    serverConn = new net.Socket();
    
    try {
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error("Connection timeout - receiver not responding"));
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
        serverConn.connect(targetPort, forwardIp);
      });
      
      // Receiver connection established - process buffered frames first
      logAttack(`[MITM] Receiver connection established, forwarding ${senderFrameBuffer.length} buffered frames`, "info");
      
      // Forward all buffered frames to receiver BEFORE marking as ready
      // This ensures buffered frames are sent in order before new frames
      for (const bufferedFrame of senderFrameBuffer) {
        await processAndForwardFrame(bufferedFrame, clientConn, serverConn, "sender->receiver");
      }
      senderFrameBuffer = []; // Clear buffer
      
      // Now mark as ready so new frames can be processed immediately
      receiverReady = true;
      // Activate attacks automatically when MITM connection is established
      if (!attackActive) {
        attackActive = true;
        logAttack(`[MITM] Attacks activated automatically - mode: ${mode}`, "success");
      }
      
      logAttack(`[MITM] Successfully connected to receiver at ${forwardIp}:${targetPort}`, "success");
      logAttack(`[MITM] Starting bidirectional relay with attack modes`, "info");
      logAttack(`[MITM] Relay active: Sender <-> Attacker <-> Receiver`, "success");
      logAttack(`[MITM] Attack mode: ${mode} - attacks will be applied to intercepted traffic`, "success");
      if (mode === "drop" && dropRate > 0) {
        logAttack(`[MITM] Drop rate: ${dropRate}%`, "info");
      }
      if (mode === "delay" && delayMs > 0) {
        logAttack(`[MITM] Delay: ${delayMs}ms`, "info");
      }
      if (mode === "modify") {
        logAttack(`[MITM] Modify text: "${modifyText}"`, "info");
      }
      sendUi(ws, { type: "status", status: `MITM active: sender <-> attacker <-> receiver (${forwardIp}:${targetPort}). Attack mode: ${mode} - ACTIVE` });

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

      // Start receiver->sender relay (receiver connection is already established)
      const relayPromise2 = relay(serverConn, clientConn, "receiver->sender").catch((e) => {
        logUi(ws, "attacker", `Relay error (r->s): ${e.message}`);
      }).finally(() => {
        // When one relay stops, cleanup the other
        cleanupConnections();
      });
      
      // Wait for sender relay to complete (it's already running and buffering)
      senderRelayPromise.catch((e) => {
        logUi(ws, "attacker", `Sender relay error: ${e.message}`);
      }).finally(() => {
        cleanupConnections();
      });
    } catch (e) {
      const errorMsg = e.message || "Unknown error";
      logAttack(`[MITM] Failed to connect to receiver at ${actualTargetIp}:${targetPort}: ${errorMsg}`, "failed");
      logAttack(`[MITM] Troubleshooting:`, "warning");
      logAttack(`[MITM] 1. Ensure receiver is running and listening on ${actualTargetIp}:${targetPort}`, "warning");
      logAttack(`[MITM] 2. Check that receiver IP (${actualTargetIp}) is correct`, "warning");
      logAttack(`[MITM] 3. Verify both devices are on the same network`, "warning");
      logAttack(`[MITM] 4. Check firewall settings on receiver device`, "warning");
      sendUi(ws, { type: "error", error: `Failed to connect to receiver: ${errorMsg}. Check that receiver is running on ${actualTargetIp}:${targetPort} and IP is correct.` });
      
      // Don't immediately close sender connection - give it a chance to retry
      // Instead, send an error frame to the sender so it knows what happened
      try {
        if (clientConn && !clientConn.destroyed) {
          // Send error frame to sender to inform about receiver connection failure
          const errorPayload = Buffer.from(JSON.stringify({ 
            reason: "receiver_unavailable", 
            message: `Attacker could not connect to receiver at ${actualTargetIp}:${targetPort}` 
          }), "utf8");
          clientConn.write(encodeFrame(FRAME_TYPES.ERROR, errorPayload));
          // Give sender time to read the error before closing
          setTimeout(() => {
            try {
              if (clientConn && !clientConn.destroyed) {
                clientConn.end();
                clientConn.destroy();
              }
            } catch {}
          }, 1000);
        }
        if (serverConn) {
          serverConn.end();
          serverConn.destroy();
        }
      } catch {}
      clientConn = null;
      serverConn = null;
      receiverReady = false;
      senderFrameBuffer = [];
      isHandlingClient = false;
    }
  }
  
  // Helper function to process and forward a frame with attack logic
  async function processAndForwardFrame(frame, src, dst, direction) {
    if (!dst || dst.destroyed || dst.closed) {
      return;
    }
    
    const fromSender = direction === "sender->receiver";
    const fromReceiver = direction === "receiver->sender";
    
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
    
    // For passive mode, try to extract and display plaintext (only for DATA frames)
    if (mode === "passive" && frame.type === FRAME_TYPES.DATA) {
      const plaintext = extractPlaintext(frame);
      if (plaintext !== null) {
        logAttack(`[PASSIVE] Plaintext message: "${plaintext}"`, "success");
      } else {
        logAttack(`[PASSIVE] Encrypted DATA frame (cannot decrypt)`, "warning");
      }
    }
    
    // Log frame details (less verbose for passive mode)
    if (mode !== "passive" || frame.type === FRAME_TYPES.DATA || frame.type === FRAME_TYPES.HELLO) {
      const rawHex = frame.payload.toString("hex");
      logUi(
        ws,
        "attacker",
        `${direction} frame type=${frame.type} len=${frame.payload.length}${mode === "passive" ? "" : ` raw-hex=${rawHex.slice(0, 64)}...`}`
      );
    }
    
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

    // Attack logic - only apply if attack is active
    let outFrame = frame;
    let shouldForward = true;
    
    if (fromSender && attackActive) {
      // Apply attack modes to frames from sender to receiver
      
      // DROP mode: Randomly drop frames based on dropRate
      if (mode === "drop" && dropRate > 0) {
        if (maybe(dropRate)) {
          logAttack(`[DROP] Dropping frame per dropRate (${dropRate}%)`, "warning");
          shouldForward = false; // Don't forward this frame
        } else {
          logAttack(`[DROP] Forwarding frame (not dropped)`, "info");
        }
      }
      
      // DELAY mode: Delay frames before forwarding
      if (mode === "delay" && delayMs > 0 && shouldForward) {
        logAttack(`[DELAY] Delaying frame by ${delayMs}ms`, "info");
        await new Promise((r) => setTimeout(r, delayMs));
      }
      
      // MODIFY mode: Modify plaintext DATA frames
      if (mode === "modify" && frame.type === FRAME_TYPES.DATA && shouldForward) {
        try {
          const plaintext = extractPlaintext(frame);
          if (plaintext !== null) {
            // This is plaintext - we can modify it
            const obj = JSON.parse(frame.payload.toString("utf8"));
            const originalText = obj.text;
            obj.text = modifyText;
            const newPayload = Buffer.from(JSON.stringify(obj), "utf8");
            outFrame = { ...frame, payload: newPayload };
            logAttack(`[MODIFY] Modified plaintext DATA frame: "${originalText}" -> "${modifyText}"`, "success");
            sendUi(ws, { type: "attackSuccess", message: `Successfully modified plaintext message: "${originalText}" -> "${modifyText}"` });
          } else {
            // Encrypted payload - cannot modify
            logAttack("[MODIFY] Attack failed: message is encrypted (cannot modify ciphertext)", "failed");
            sendUi(ws, { type: "attackFailed", message: "Modify attack failed: message is encrypted (cannot modify ciphertext without decryption key)" });
          }
        } catch (e) {
          // If we can't parse as JSON, it's likely encrypted
          logAttack(`[MODIFY] Attack failed: cannot parse payload (likely encrypted): ${e.message}`, "failed");
          sendUi(ws, { type: "attackFailed", message: "Modify attack failed: cannot parse encrypted payload" });
        }
      }
      
      // REPLAY mode: Replay the last DATA frame instead of current one
      if (mode === "replay" && frame.type === FRAME_TYPES.DATA && shouldForward) {
        if (lastFrameFromSender) {
          // Replay the last DATA frame instead of the current one
          // Use a deep copy to avoid modifying the stored frame
          const replayFrame = {
            type: lastFrameFromSender.type,
            payload: Buffer.from(lastFrameFromSender.payload)
          };
          outFrame = replayFrame;
          logAttack("[REPLAY] Replaying last DATA frame instead of current", "warning");
          sendUi(ws, { type: "attackSuccess", message: "Replaying last DATA frame" });
          // Note: This will likely fail if encryption mode has replay protection
        } else {
          // First message - forward normally, will be stored below
          logAttack("[REPLAY] First DATA frame - storing for future replay", "info");
        }
      }
      
      // Store last DATA frame for replay mode (store original before any modifications)
      // Store AFTER replay check so we don't lose the previous frame
      if (frame.type === FRAME_TYPES.DATA) {
        // Deep copy the ORIGINAL frame to avoid reference issues
        // Store it before any modifications so replay uses the original message
        lastFrameFromSender = {
          type: frame.type,
          payload: Buffer.from(frame.payload)
        };
      }
      
      // DOWNGRADE mode: Modify HELLO frame to force plaintext
      if (mode === "downgrade" && frame.type === FRAME_TYPES.HELLO && shouldForward) {
        try {
          const hello = JSON.parse(frame.payload.toString("utf8"));
          const originalMode = hello.encMode;
          if (originalMode !== 0) {
            hello.encMode = 0; // force plaintext
            const newPayload = Buffer.from(JSON.stringify(hello), "utf8");
            outFrame = { ...frame, payload: newPayload };
            logAttack(`[DOWNGRADE] Attempted downgrade from mode ${originalMode} to plaintext (mode 0) in HELLO`, "warning");
            sendUi(ws, { type: "attackSuccess", message: `Attempted downgrade attack: mode ${originalMode} -> 0` });
            // Note: We'll detect failure when receiver sends ERROR frame
          } else {
            logAttack("[DOWNGRADE] HELLO already in plaintext mode, no downgrade needed", "info");
          }
        } catch (e) {
          logAttack(`[DOWNGRADE] Attack failed: cannot parse HELLO: ${e.message}`, "failed");
          sendUi(ws, { type: "attackFailed", message: "Downgrade attack failed: cannot parse HELLO" });
        }
      }
    }
    // Note: If attackActive is false, frames are still relayed but attacks are not applied

    // Forward - check connection state before writing
    if (!shouldForward) {
      // Frame was dropped, skip forwarding
      return;
    }
    
    if (!dst || dst.destroyed || dst.closed) {
      logAttack(`Destination connection closed, cannot forward: ${direction}`, "warning");
      return;
    }
    
    try {
      const encoded = encodeFrame(outFrame.type, outFrame.payload);
      // Check if socket is writable before writing
      if (!dst.writable) {
        logAttack(`Destination socket not writable, cannot forward: ${direction}`, "warning");
        return;
      }
      const written = dst.write(encoded);
      // Handle backpressure (though unlikely with our frame sizes)
      if (!written) {
        await new Promise((resolve) => dst.once("drain", resolve));
      }
      // Log successful forwarding for non-passive modes
      if (attackActive && mode !== "passive" && fromSender) {
        logAttack(`[${mode.toUpperCase()}] Frame forwarded successfully`, "info");
      }
    } catch (e) {
      logAttack(`Failed to write frame in ${direction}: ${e.message}`, "failed");
      throw e; // Re-throw to let caller handle
    }
  }

  async function relay(src, dst, direction) {
    // This relay function is only used for receiver->sender direction now
    // sender->receiver is handled by the buffering logic in handleNewClient
    const frameIter = decodeFrames(src);
    
    for await (const frame of frameIter) {
      if (!running) break;
      
      // Use the shared frame processing function
      try {
        await processAndForwardFrame(frame, src, dst, direction);
      } catch (e) {
        logAttack(`Relay error in ${direction}: ${e.message}`, "failed");
        break; // Exit relay loop on error
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
    // Update target IP from config (victim's IP - the receiver that attacker proxies to)
    if (attackConfig.targetIp) {
      targetIp = attackConfig.targetIp;
    }
    
    // Update attack configuration FIRST (this sets the mode)
    updateAttackConfig(attackConfig);
    
    if (!targetIp) {
      logAttack("ERROR: Victim IP (target IP) is required. Please enter victim's IP address.", "failed");
      sendUi(ws, { type: "error", error: "Victim IP is required. Please enter the target IP address." });
      attackActive = false;
      return;
    }
    
    // Activate attack AFTER config is updated
    attackActive = true;
    
    logAttack(`[ATTACK STARTED] Mode: ${mode}, Victim: ${targetIp}:${targetPort}`, "info");
    if (mode === "drop" && dropRate > 0) {
      logAttack(`[ATTACK STARTED] Drop rate: ${dropRate}%`, "info");
    }
    if (mode === "delay" && delayMs > 0) {
      logAttack(`[ATTACK STARTED] Delay: ${delayMs}ms`, "info");
    }
    if (mode === "modify") {
      logAttack(`[ATTACK STARTED] Modify text: "${modifyText}"`, "info");
    }
    sendUi(ws, { type: "status", status: `Attack active: ${mode} mode, victim: ${targetIp}:${targetPort}` });
    
    // The attacker listens and intercepts when sender connects
    if (!server) {
      logAttack("Attacker server not ready. Please wait for server to start.", "warning");
      attackActive = false;
      return;
    }
    
    logAttack("Attacker is ready. Waiting for sender to connect...", "info");
    if (targetIp) {
      logAttack(`[MITM] Sender should connect to attacker's IP (shown in Local IP)`, "info");
      logAttack(`[MITM] Attacker will intercept and forward to receiver at ${targetIp}:${targetPort}`, "info");
      logAttack(`[MITM] Attacker is invisible - not discoverable by sender or receiver`, "info");
      logAttack(`[MITM] Attack modes will be applied to intercepted traffic`, "info");
    } else {
      logAttack(`[MITM] Configure receiver's IP in Target IP field`, "warning");
      logAttack(`[MITM] Attacker is listening and will intercept connections`, "info");
    }
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
