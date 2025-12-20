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
  let mode = config.attackMode || "modify";
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

  // Helper function to reset connection state for reconnection
  function resetConnectionState() {
    negotiatedEncMode = null;
    senderFrameBuffer = [];
    receiverReady = false;
    lastFrameFromSender = null;
    lastFrameFromReceiver = null;
    logAttack(`[RECONNECT] Connection state reset - ready for new connection with any encryption mode`, "info");
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
        try {
          logAttack(`[MITM] New connection received from ${c.remoteAddress}:${c.remotePort}`, "info");
          
          // If there's an existing connection, close it first
          if (clientConn) {
            try {
              logAttack(`[RECONNECT] Closing previous sender connection to accept new connection`, "info");
              logAttack(`[RECONNECT] New connection will use new encryption mode if changed`, "info");
              clientConn.end();
              clientConn.destroy();
            } catch {}
            clientConn = null;
            // Reset encryption mode tracking for new connection
            negotiatedEncMode = null;
          }
          // Don't close serverConn here - keep receiver connection if it exists
          
          // Prevent concurrent handling - but allow if previous connection is dead
          if (isHandlingClient) {
            // Check if previous connection is still valid
            if (clientConn && !clientConn.destroyed) {
              logAttack("New connection rejected: already handling a connection", "warning");
              try {
                c.end();
                c.destroy();
              } catch {}
              return;
            } else {
              // Previous connection is dead, reset flag and allow new connection
              logAttack("Previous connection dead, accepting new connection", "info");
              isHandlingClient = false;
              clientConn = null;
            }
          }
          
          clientConn = c;
          isHandlingClient = true;
          
          // CRITICAL: Protect connection IMMEDIATELY - prevent it from being destroyed
          // Set up error/close handlers to catch any issues before handleNewClient() runs
          const onClientErrorImmediate = (err) => {
            try {
              logAttack(`[MITM] Sender connection error: ${err.message}`, "failed");
            } catch {}
            // Connection error - mark for cleanup but don't destroy yet
            // Let handleNewClient() handle proper cleanup
            if (clientConn === c) {
              // Connection is now invalid, but keep reference for cleanup
            }
          };
          const onClientCloseImmediate = () => {
            try {
              logAttack(`[MITM] Sender disconnected`, "warning");
            } catch {}
            // Client disconnected - mark connection as closed
            if (clientConn === c) {
              clientConn = null;
            }
          };
          
          // Set up handlers IMMEDIATELY to prevent unhandled errors from destroying connection
          c.on("error", onClientErrorImmediate);
          c.on("close", onClientCloseImmediate);
          
          // Configure connection to stay alive and healthy
          c.setKeepAlive(true, 60000); // Keep connection alive with 60s keepalive
          c.setNoDelay(true); // Disable Nagle's algorithm for lower latency
          c.setTimeout(0); // Disable timeout - we'll handle timeouts ourselves if needed
          
          // Pause the connection temporarily to prevent data loss during setup
          // We'll resume it in handleNewClient() once everything is ready
          c.pause();
          
          handleNewClient().catch((e) => {
            // Better error handling to prevent WebSocket disconnection
            try {
              logUi(ws, "attacker", `Client handling error: ${e.message}`);
              log("attacker", `Client handling error: ${e.message}`);
              if (e.stack) {
                log("attacker", `Stack: ${e.stack}`);
              }
            } catch (logError) {
              // If logging fails, at least log to console
              console.error("Attacker error logging failed:", logError);
              console.error("Original error:", e);
            }
          });
          // Note: isHandlingClient is reset in handleNewClient's finally block
        } catch (e) {
          // Catch any errors in the connection handler itself
          try {
            log("attacker", `Error in connection handler: ${e.message}`);
            console.error("Error in connection handler:", e);
            try {
              c.end();
              c.destroy();
            } catch {}
          } catch {}
        }
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
        try {
          logUi(ws, "attacker", `Server error: ${err.message}`);
          sendUi(ws, { type: "error", error: `Server error: ${err.message}` });
        } catch (e) {
          log("attacker", `Server error: ${err.message}`);
          console.error("Error sending server error to UI:", e);
        }
      });
    } catch (e) {
      try {
        logUi(ws, "attacker", `Attacker failed to start: ${e.message}`);
        sendUi(ws, { type: "error", error: e.message });
      } catch (sendError) {
        log("attacker", `Attacker failed to start: ${e.message}`);
        console.error("Error sending startup error to UI:", sendError);
      }
    }
  })().catch((e) => {
    // Catch any unhandled errors in the async IIFE
    log("attacker", `Unhandled error in attacker initialization: ${e.message}`);
    if (e.stack) {
      log("attacker", `Stack: ${e.stack}`);
    }
    console.error("Unhandled error in attacker:", e);
  });

  async function handleNewClient() {
    try {
      // Check connection validity immediately at the start
      // The connection might have been destroyed by the client disconnecting
      if (!clientConn || clientConn.destroyed || clientConn.closed) {
        // Client disconnected before we could process the connection - this is normal
        logAttack(`[MITM] Client disconnected before connection could be established`, "info");
        clientConn = null;
        isHandlingClient = false;
        return;
      }
      
      // Don't close serverConn here - keep receiver connection if it exists
      
      // Reset state for new connection
      senderFrameBuffer = [];
      // Reset encryption mode tracking for new connection (will be detected from HELLO frame)
      negotiatedEncMode = null;
      // Don't reset receiverReady here - keep it if receiver is already connected
      
      // Use targetIp as the victim's IP (receiver that attacker proxies to)
      const actualTargetIp = targetIp;
      
      if (!actualTargetIp) {
        logUi(ws, "attacker", "ERROR: Victim IP (target IP) not configured. Please enter victim's IP address.");
        sendUi(ws, { type: "error", error: "Victim IP (target IP) not configured. Please enter the victim's IP address in Target IP field." });
        try {
          if (clientConn && !clientConn.destroyed) {
            clientConn.end();
            clientConn.destroy();
          }
        } catch {}
        clientConn = null;
        isHandlingClient = false;
        return;
      }
      
      // Double-check connection is still valid after configuration check
      if (!clientConn || clientConn.destroyed || clientConn.closed) {
        logAttack(`[MITM] Client disconnected during setup`, "info");
        clientConn = null;
        isHandlingClient = false;
        return;
      }
    
    logAttack(`[MITM] Sender connected to attacker`, "success");
    
    // Resume connection now that we're ready to process data
    // We paused it earlier to prevent data loss during setup
    if (clientConn && !clientConn.destroyed && !clientConn.closed) {
      clientConn.resume();
    }
    
    // Start buffering frames from sender immediately (before receiver connection is ready)
    const senderRelayPromise = (async () => {
      try {
        const frameIter = decodeFrames(clientConn);
        for await (const frame of frameIter) {
          if (!running || !clientConn) break;
          
          // If receiver is not ready, buffer the frame
          if (!receiverReady || !serverConn || serverConn.destroyed) {
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
    
    // If receiver is not connected, try to connect automatically
    if (!receiverReady || !serverConn || serverConn.destroyed) {
      logAttack(`[MITM] Receiver not connected. Attempting to connect automatically...`, "info");
      
      // Try to connect to receiver automatically
      const forwardIp = actualTargetIp;
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
            if (serverConn && !serverConn.destroyed) {
              try {
                serverConn.removeAllListeners("error");
              } catch {}
            }
            resolve();
          });
          serverConn.connect(targetPort, forwardIp);
        });
        
        // Receiver connection established
        receiverReady = true;
        logAttack(`[MITM] Successfully connected to receiver at ${forwardIp}:${targetPort}`, "success");
        logAttack(`[MITM] Forwarding ${senderFrameBuffer.length} buffered frames`, "info");
        
        // Forward all buffered frames to receiver
        for (const bufferedFrame of senderFrameBuffer) {
          await processAndForwardFrame(bufferedFrame, clientConn, serverConn, "sender->receiver");
        }
        senderFrameBuffer = []; // Clear buffer
        
        // Set up error handlers for receiver connection
        serverConn.on("error", (err) => {
          logAttack(`[DISCONNECT] Receiver connection error: ${err.message}`, "failed");
          logAttack(`[RECONNECT] Receiver disconnected. Will auto-reconnect when sender connects, or click 'Connect to Receiver' to reconnect now.`, "info");
          receiverReady = false;
          if (serverConn) {
            serverConn = null;
          }
          // Reset encryption mode tracking
          negotiatedEncMode = null;
          sendUi(ws, { type: "error", error: `Receiver connection lost: ${err.message}. Will auto-reconnect on next sender connection.` });
        });
        
        serverConn.on("close", () => {
          logAttack("[DISCONNECT] Receiver connection closed", "warning");
          logAttack(`[RECONNECT] Receiver disconnected. Will auto-reconnect when sender connects, or click 'Connect to Receiver' to reconnect now.`, "info");
          receiverReady = false;
          serverConn = null;
          // Reset encryption mode tracking
          negotiatedEncMode = null;
          sendUi(ws, { type: "status", status: "Receiver connection closed. Will auto-reconnect when sender connects, or click 'Connect to Receiver' to reconnect now." });
        });
        
        // Start listening for frames from receiver (for relay back to sender)
        (async () => {
          try {
            if (serverConn && !serverConn.destroyed) {
              const frameIter = decodeFrames(serverConn);
              for await (const frame of frameIter) {
                if (!running || !serverConn || serverConn.destroyed) break;
                
                // If sender is not connected yet, we can't forward - just log
                if (!clientConn || clientConn.destroyed) {
                  logAttack(`[MITM] Received frame from receiver but sender not connected yet`, "warning");
                  continue;
                }
                
                // Forward to sender
                await processAndForwardFrame(frame, serverConn, clientConn, "receiver->sender");
              }
            }
          } catch (e) {
            if (running && serverConn) {
              logAttack(`Receiver relay error: ${e.message}`, "failed");
            }
          }
        })();
        
      } catch (e) {
        const errorMsg = e.message || "Unknown error";
        logAttack(`[MITM] Failed to connect to receiver at ${forwardIp}:${targetPort}: ${errorMsg}`, "failed");
        logAttack(`[MITM] Sender frames will be buffered. Click 'Connect to Receiver' to establish connection.`, "warning");
        sendUi(ws, { type: "error", error: `Failed to connect to receiver: ${errorMsg}. Sender frames are being buffered. Click 'Connect to Receiver' to retry.` });
        
        if (serverConn) {
          try {
            serverConn.end();
            serverConn.destroy();
          } catch {}
          serverConn = null;
        }
        receiverReady = false;
        // Don't close sender connection - keep it open and buffer frames
      }
    } else {
      logAttack(`[MITM] Receiver already connected`, "info");
    }
    
      logAttack(`[MITM] Attacker is in the middle: Sender -> Attacker -> Receiver`, "success");

      // Activate attacks automatically when MITM connection is established
      if (!attackActive) {
        attackActive = true;
        logAttack(`[MITM] Attacks activated automatically - mode: ${mode}`, "success");
      }
      
      logAttack(`[MITM] Sender connected, starting bidirectional relay`, "success");
      logAttack(`[MITM] Relay active: Sender <-> Attacker <-> Receiver`, "success");
      logAttack(`[MITM] Attack mode: ${mode} - attacks will be applied to intercepted traffic`, "success");
      if (mode === "modify") {
        logAttack(`[MITM] Interception will attempt to modify ALL messages (plaintext and encrypted)`, "info");
        logAttack(`[MITM] Plaintext messages: Will be modified successfully`, "info");
        logAttack(`[MITM] Encrypted messages: Interception will fail (showing encryption protection works)`, "info");
      }
      if (mode === "drop" && dropRate > 0) {
        logAttack(`[MITM] Drop rate: ${dropRate}%`, "info");
      }
      if (mode === "delay" && delayMs > 0) {
        logAttack(`[MITM] Delay: ${delayMs}ms`, "info");
      }
      if (mode === "modify") {
        logAttack(`[MITM] Modify text: "${modifyText}"`, "info");
      }
      sendUi(ws, { type: "status", status: `MITM active: sender <-> attacker <-> receiver. Attack mode: ${mode} - ACTIVE` });

      // Add error and close handlers to detect connection failures
      const cleanupConnections = () => {
        if (clientConn && !clientConn.destroyed) {
          try {
            clientConn.removeAllListeners();
            clientConn.end();
            clientConn.destroy();
          } catch {}
        }
        clientConn = null;
        if (serverConn && !serverConn.destroyed) {
          try {
            serverConn.removeAllListeners();
            serverConn.end();
            serverConn.destroy();
          } catch {}
        }
        serverConn = null;
        isHandlingClient = false;
        // Reset all connection state for easy reconnection
        resetConnectionState();
      };

      // Replace early handlers with proper cleanup handlers
      // Remove the immediate handlers we set up earlier
      clientConn.removeAllListeners("error");
      clientConn.removeAllListeners("close");
      
      const onClientError = (err) => {
        try {
          logAttack(`[DISCONNECT] Sender connection error: ${err.message}`, "failed");
          logAttack(`[RECONNECT] Ready to accept new sender connection (encryption mode changes may require reconnection)`, "info");
        } catch {}
        cleanupConnections();
        // Reset encryption mode tracking for new connection
        negotiatedEncMode = null;
      };
      const onClientClose = () => {
        try {
          logAttack("[DISCONNECT] Sender connection closed", "warning");
          logAttack(`[RECONNECT] Ready to accept new sender connection. Sender can reconnect with any encryption mode.`, "info");
        } catch {}
        cleanupConnections();
        // Reset encryption mode tracking for new connection
        negotiatedEncMode = null;
      };

      clientConn.on("error", onClientError);
      clientConn.on("close", onClientClose);
      // Note: serverConn error/close handlers are already set up in connectToReceiver

      // Wait for sender relay to complete
      senderRelayPromise.catch((e) => {
        try {
          logUi(ws, "attacker", `Sender relay error: ${e.message}`);
        } catch {}
      }).finally(() => {
        cleanupConnections();
      });
    } catch (e) {
      // Catch any errors in handleNewClient to prevent WebSocket disconnection
      try {
        logUi(ws, "attacker", `Error in handleNewClient: ${e.message}`);
        log("attacker", `Error in handleNewClient: ${e.message}`);
        if (e.stack) {
          log("attacker", `Stack: ${e.stack}`);
        }
      } catch (logError) {
        console.error("Error logging failed:", logError);
        console.error("Original error:", e);
      }
      
      // Clean up on error - ensure flag is always reset
      try {
        if (clientConn && !clientConn.destroyed) {
          clientConn.end();
          clientConn.destroy();
        }
      } catch {}
      clientConn = null;
    } finally {
      // Always reset the flag, even if there was an error
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
        const previousEncMode = negotiatedEncMode;
        negotiatedEncMode = hello.encMode;
        const encModeName = negotiatedEncMode === ENC_MODES.PLAINTEXT ? "Plaintext" :
                           negotiatedEncMode === ENC_MODES.AES_GCM ? "AES-GCM" :
                           negotiatedEncMode === ENC_MODES.AES_CBC_HMAC ? "AES-CBC+HMAC" :
                           negotiatedEncMode === ENC_MODES.DIFFIE_HELLMAN ? "Diffie-Hellman" :
                           `Mode ${negotiatedEncMode}`;
        
        if (previousEncMode !== null && previousEncMode !== negotiatedEncMode) {
          logAttack(`[RECONNECT] Encryption mode changed: ${previousEncMode} → ${negotiatedEncMode} (${encModeName})`, "info");
          logAttack(`[RECONNECT] New connection established with updated encryption settings`, "success");
        } else {
          logAttack(`[INTERCEPTION] Detected encryption mode: ${encModeName}`, "info");
        }
        
        if (negotiatedEncMode !== ENC_MODES.PLAINTEXT) {
          logAttack(`[INTERCEPTION] Messages will be encrypted - modification attempts will fail without decryption key`, "warning");
        }
      } catch (e) {
        // Ignore parse errors
      }
    }
    
    // For passive mode, try to extract and display plaintext (only for DATA frames)
    if (mode === "passive" && frame.type === FRAME_TYPES.DATA) {
      const plaintext = extractPlaintext(frame);
      if (plaintext !== null) {
        logAttack(`[PASSIVE] Plaintext message intercepted: "${plaintext}"`, "success");
      } else {
        const encModeName = negotiatedEncMode === ENC_MODES.AES_GCM ? "AES-GCM" :
                           negotiatedEncMode === ENC_MODES.AES_CBC_HMAC ? "AES-CBC+HMAC" :
                           negotiatedEncMode === ENC_MODES.DIFFIE_HELLMAN ? "Diffie-Hellman" :
                           "Encrypted";
        logAttack(`[PASSIVE] Encrypted DATA frame (${encModeName}) - cannot decrypt without key`, "warning");
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
      
      // MODIFY mode: Attempt to intercept and modify ALL DATA frames (plaintext and encrypted)
      if (mode === "modify" && frame.type === FRAME_TYPES.DATA && shouldForward) {
        // Always attempt interception - works for all encryption modes
        const isPlaintext = negotiatedEncMode === ENC_MODES.PLAINTEXT || negotiatedEncMode === null;
        const encModeName = negotiatedEncMode === ENC_MODES.PLAINTEXT ? "Plaintext" :
                           negotiatedEncMode === ENC_MODES.AES_GCM ? "AES-GCM" :
                           negotiatedEncMode === ENC_MODES.AES_CBC_HMAC ? "AES-CBC+HMAC" :
                           negotiatedEncMode === ENC_MODES.DIFFIE_HELLMAN ? "Diffie-Hellman" :
                           negotiatedEncMode !== null ? `Mode ${negotiatedEncMode}` : "Unknown";
        
        // Log interception attempt for all encryption modes
        logAttack(`[INTERCEPTION ATTEMPT] Intercepting DATA frame (${encModeName})`, "info");
        
        try {
          const plaintext = extractPlaintext(frame);
          if (plaintext !== null || isPlaintext) {
            // This is plaintext - we can modify it
            try {
              const obj = JSON.parse(frame.payload.toString("utf8"));
              const originalText = obj.text || "[unknown]";
              obj.text = modifyText;
              const newPayload = Buffer.from(JSON.stringify(obj), "utf8");
              outFrame = { ...frame, payload: newPayload };
              logAttack(`[INTERCEPTION SUCCESS] Modified plaintext message: "${originalText}" -> "${modifyText}"`, "success");
              sendUi(ws, { 
                type: "attackSuccess", 
                message: `✓ INTERCEPTION SUCCESS: Modified plaintext message "${originalText}" -> "${modifyText}"` 
              });
            } catch (parseError) {
              // Couldn't parse as JSON - might be malformed plaintext
              logAttack(`[INTERCEPTION FAILED] Cannot parse message (malformed or encrypted): ${parseError.message}`, "failed");
              sendUi(ws, { 
                type: "attackFailed", 
                message: `✗ INTERCEPTION FAILED: Cannot parse message - may be encrypted or malformed` 
              });
            }
          } else {
            // Encrypted payload - cannot modify without decryption key
            const encModeName = negotiatedEncMode === ENC_MODES.AES_GCM ? "AES-GCM" : 
                               negotiatedEncMode === ENC_MODES.AES_CBC_HMAC ? "AES-CBC+HMAC" : 
                               "Encrypted";
            logAttack(`[INTERCEPTION FAILED] Message is encrypted (${encModeName}) - cannot modify ciphertext without decryption key`, "failed");
            sendUi(ws, { 
              type: "attackFailed", 
              message: `✗ INTERCEPTION FAILED: Message is encrypted (${encModeName}). Cannot modify ciphertext without decryption key. Encryption is protecting the message.` 
            });
          }
        } catch (e) {
          // If we can't parse as JSON, it's likely encrypted
          const encModeName = negotiatedEncMode === ENC_MODES.AES_GCM ? "AES-GCM" : 
                             negotiatedEncMode === ENC_MODES.AES_CBC_HMAC ? "AES-CBC+HMAC" : 
                             "Encrypted";
          logAttack(`[INTERCEPTION FAILED] Cannot parse payload (encrypted with ${encModeName}): ${e.message}`, "failed");
          sendUi(ws, { 
            type: "attackFailed", 
            message: `✗ INTERCEPTION FAILED: Message is encrypted (${encModeName}). Cannot modify without decryption key.` 
          });
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

  async function connectToReceiver(connectConfig) {
    // Proactively connect to receiver (before sender connects)
    if (connectConfig && connectConfig.targetIp) {
      targetIp = connectConfig.targetIp;
    }
    
    if (!targetIp) {
      logAttack("ERROR: Victim IP (target IP) is required. Please enter victim's IP address.", "failed");
      sendUi(ws, { type: "error", error: "Victim IP is required. Please enter the target IP address." });
      return;
    }
    
    // Clean up existing receiver connection if any
    if (serverConn) {
      try {
        logAttack(`[RECONNECT] Closing existing receiver connection before reconnecting`, "info");
        serverConn.end();
        serverConn.destroy();
      } catch {}
      serverConn = null;
    }
    
    // Reset state for clean reconnection
    resetConnectionState();
    
    const forwardIp = targetIp;
    logAttack(`[MITM] Connecting to receiver at ${forwardIp}:${targetPort}...`, "info");
    
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
          if (serverConn && !serverConn.destroyed) {
            try {
              serverConn.removeAllListeners("error");
            } catch {}
          }
          resolve();
        });
        serverConn.connect(targetPort, forwardIp);
      });
      
      // Receiver connection established
      receiverReady = true;
      logAttack(`[MITM] Successfully connected to receiver at ${forwardIp}:${targetPort}`, "success");
      logAttack(`[MITM] Ready to intercept sender connections`, "info");
      sendUi(ws, { type: "status", status: `Connected to receiver at ${forwardIp}:${targetPort}. Waiting for sender to connect...` });
      
      // Set up error handlers for receiver connection
        serverConn.on("error", (err) => {
          logAttack(`[DISCONNECT] Receiver connection error: ${err.message}`, "failed");
          logAttack(`[RECONNECT] Receiver disconnected. Will auto-reconnect when sender connects, or click 'Connect to Receiver' to reconnect now.`, "info");
          receiverReady = false;
          serverConn = null;
          // Reset encryption mode tracking
          negotiatedEncMode = null;
          sendUi(ws, { type: "error", error: `Receiver connection lost: ${err.message}. Will auto-reconnect on next sender connection.` });
        });
        
        serverConn.on("close", () => {
          logAttack("[DISCONNECT] Receiver connection closed", "warning");
          logAttack(`[RECONNECT] Receiver disconnected. Will auto-reconnect when sender connects, or click 'Connect to Receiver' to reconnect now.`, "info");
          receiverReady = false;
          serverConn = null;
          // Reset encryption mode tracking
          negotiatedEncMode = null;
          sendUi(ws, { type: "status", status: "Receiver connection closed. Will auto-reconnect when sender connects, or click 'Connect to Receiver' to reconnect now." });
        });
      
      // Start listening for frames from receiver (for relay back to sender)
      // This will be used when sender connects
      (async () => {
        try {
          if (serverConn && !serverConn.destroyed) {
            const frameIter = decodeFrames(serverConn);
            for await (const frame of frameIter) {
              if (!running || !serverConn || serverConn.destroyed) break;
              
              // If sender is not connected yet, we can't forward - just log
              if (!clientConn || clientConn.destroyed) {
                logAttack(`[MITM] Received frame from receiver but sender not connected yet`, "warning");
                continue;
              }
              
              // Forward to sender
              await processAndForwardFrame(frame, serverConn, clientConn, "receiver->sender");
            }
          }
        } catch (e) {
          if (running && serverConn) {
            logAttack(`Receiver relay error: ${e.message}`, "failed");
          }
        }
      })();
      
    } catch (e) {
      const errorMsg = e.message || "Unknown error";
      logAttack(`[MITM] Failed to connect to receiver at ${forwardIp}:${targetPort}: ${errorMsg}`, "failed");
      logAttack(`[MITM] Troubleshooting:`, "warning");
      logAttack(`[MITM] 1. Ensure receiver is running and listening on ${forwardIp}:${targetPort}`, "warning");
      logAttack(`[MITM] 2. Check that receiver IP (${forwardIp}) is correct`, "warning");
      logAttack(`[MITM] 3. Verify both devices are on the same network`, "warning");
      logAttack(`[MITM] 4. Check firewall settings on receiver device`, "warning");
      sendUi(ws, { type: "error", error: `Failed to connect to receiver: ${errorMsg}. Check that receiver is running on ${forwardIp}:${targetPort} and IP is correct.` });
      
      if (serverConn) {
        try {
          serverConn.end();
          serverConn.destroy();
        } catch {}
        serverConn = null;
      }
      receiverReady = false;
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
      if (clientConn && !clientConn.destroyed) {
        clientConn.removeAllListeners();
        clientConn.end();
        clientConn.destroy();
      }
      clientConn = null;
    } catch {}
    try {
      if (serverConn && !serverConn.destroyed) {
        serverConn.removeAllListeners();
        serverConn.end();
        serverConn.destroy();
      }
      serverConn = null;
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
    async connectToReceiver(config) {
      await connectToReceiver(config);
    },
    async updateAttackConfig(newConfig) {
      updateAttackConfig(newConfig);
    },
    async updateSecurityConfig(newConfig) {
      // Attacker doesn't use security config, but implement for consistency
      updateAttackConfig(newConfig);
    },
    checkHandshake() {
      const isComplete = clientConn && serverConn && receiverReady;
      return {
        complete: isComplete,
        status: isComplete ? "MITM relay active - connections established" : (serverConn && receiverReady ? "Receiver connected, waiting for sender..." : (clientConn ? "Sender connected, receiver not ready..." : (receiverReady ? "Receiver ready, waiting for sender..." : "Waiting for connections...")))
      };
    }
  };
}

module.exports = {
  createAttacker
};
