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
  const targetIp = config.targetIp || "127.0.0.1";
  const targetPort = config.port || 12347;
  const mode = config.attackMode || "passive";
  const dropRate = Number(config.dropRate || 0);
  const delayMs = Number(config.delayMs || 0);
  const modifyText = config.modifyText || "";

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
    
    logUi(ws, "attacker", "Sender connected to attacker, connecting to real receiver");
    serverConn = new net.Socket();
    
    try {
      await new Promise((resolve, reject) => {
        serverConn.once("error", reject);
        serverConn.connect(targetPort, targetIp, () => {
          serverConn.removeAllListeners("error");
          resolve();
        });
      });
      logUi(ws, "attacker", "Connected to real receiver, starting bidirectional relay");

      relay(clientConn, serverConn, "sender->receiver").catch((e) =>
        logUi(ws, "attacker", `Relay error (s->r): ${e.message}`)
      );
      relay(serverConn, clientConn, "receiver->sender").catch((e) =>
        logUi(ws, "attacker", `Relay error (r->s): ${e.message}`)
      );
    } catch (e) {
      logUi(ws, "attacker", `Failed to connect to receiver: ${e.message}`);
      sendUi(ws, { type: "error", error: `Failed to connect to receiver: ${e.message}` });
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

      // Attack logic
      let outFrame = frame;
      if (fromSender) {
        lastFrameFromSender = frame;
        if (mode === "drop" && maybe(dropRate)) {
          logUi(ws, "attacker", "Dropping frame per dropRate");
          continue;
        }
        if (mode === "replay" && lastFrameFromSender) {
          logUi(ws, "attacker", "Replaying last frame");
          outFrame = lastFrameFromSender;
        }
        if (mode === "delay" && delayMs > 0) {
          await new Promise((r) => setTimeout(r, delayMs));
        }
        if (mode === "modify" && frame.type === FRAME_TYPES.DATA) {
          try {
            const obj = JSON.parse(frame.payload.toString("utf8"));
            if (typeof obj.text === "string") {
              obj.text = modifyText || "[MITM modified]";
              const newPayload = Buffer.from(JSON.stringify(obj), "utf8");
              outFrame = { ...frame, payload: newPayload };
              logUi(ws, "attacker", "Modified plaintext DATA frame");
              sendUi(ws, { type: "attackSuccess", message: "Successfully modified plaintext message" });
            } else {
              logUi(
                ws,
                "attacker",
                "Modify mode: frame not plaintext or not understood, leaving as-is"
              );
              sendUi(ws, { type: "attackFailed", message: "Modify attack failed: message is encrypted (cannot modify ciphertext)" });
            }
          } catch {
            logUi(ws, "attacker", "Modify mode: failed to parse payload as JSON");
            sendUi(ws, { type: "attackFailed", message: "Modify attack failed: cannot parse encrypted payload" });
          }
        }
        if (mode === "downgrade" && frame.type === FRAME_TYPES.HELLO) {
          try {
            const hello = JSON.parse(frame.payload.toString("utf8"));
            hello.encMode = 0; // force plaintext
            const newPayload = Buffer.from(JSON.stringify(hello), "utf8");
            outFrame = { ...frame, payload: newPayload };
            logUi(ws, "attacker", "Attempted downgrade to plaintext in HELLO");
            // Note: We'll detect failure when receiver sends ERROR frame
          } catch {
            logUi(ws, "attacker", "Downgrade mode: failed to parse HELLO");
            sendUi(ws, { type: "attackFailed", message: "Downgrade attack failed: cannot parse HELLO" });
          }
        }
        if (mode === "replay" && lastFrameFromSender) {
          // Replay attacks will be detected as failed when receiver detects replay
          // (we'll see this in the receiver's response or lack thereof)
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
    }
  };
}

module.exports = {
  createAttacker
};


