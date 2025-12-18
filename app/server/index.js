const express = require("express");
const path = require("path");
const http = require("http");
const os = require("os");
const WebSocket = require("ws");
const { log } = require("../../core/logging/logger");
const { createSender } = require("./roles/sender");
const { createReceiver } = require("./roles/receiver");
const { createAttacker } = require("./roles/attacker");
const { startDiscovery, stopDiscovery, sendDiscoveryPing, broadcastPresence } = require("./lan/discovery");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;

function getLocalIp() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        return iface.address;
      }
    }
  }
  return "127.0.0.1";
}

app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

app.get("/api/info", (req, res) => {
  res.json({
    localIp: getLocalIp(),
    defaultPort: 12347,
    protocol: "TCP"
  });
});

let currentRole = null;
let roleInstance = null;
let discovery = null;
let broadcastInterval = null;

wss.on("connection", (ws) => {
  log("ui", "WebSocket client connected");
  ws.on("close", () => {
    // Stop broadcasting when client disconnects
    if (broadcastInterval) {
      clearInterval(broadcastInterval);
      broadcastInterval = null;
    }
  });

  ws.on("message", async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      switch (msg.type) {
        case "configureRole": {
          currentRole = msg.role;
          if (roleInstance && roleInstance.stop) {
            await roleInstance.stop();
          }
          
          // Stop previous broadcast interval
          if (broadcastInterval) {
            clearInterval(broadcastInterval);
            broadcastInterval = null;
          }
          
          const cfg = msg.config || {};
          const port = cfg.port || 12347;
          
          // Start or restart discovery with current role/port
          if (discovery && discovery.socket) {
            // Update existing discovery with new role/port
            discovery.currentRole = currentRole;
            discovery.currentPort = port;
          } else {
            discovery = startDiscovery(currentRole, port);
          }
          
          if (currentRole === "sender") {
            roleInstance = createSender(cfg, ws);
          } else if (currentRole === "receiver") {
            roleInstance = createReceiver(cfg, ws);
          } else if (currentRole === "attacker") {
            roleInstance = createAttacker(cfg, ws);
          } else {
            throw new Error("Unknown role");
          }
          
          // Broadcast presence immediately and then periodically
          broadcastPresence(discovery, currentRole, port);
          broadcastInterval = setInterval(() => {
            broadcastPresence(discovery, currentRole, port);
          }, 3000); // Broadcast every 3 seconds
          
          ws.send(JSON.stringify({ type: "status", status: `Role set to ${currentRole}` }));
          break;
        }
        case "discover": {
          const cfg = msg.config || {};
          const port = cfg.port || 12347;
          
          if (!discovery) {
            discovery = startDiscovery(currentRole, port);
          }
          // Clear previous results before new discovery
          if (discovery.peers) {
            discovery.peers.clear();
          }
          const results = await sendDiscoveryPing(discovery);
          ws.send(
            JSON.stringify({
              type: "discoveryResults",
              results: results.length > 0 ? results : []
            })
          );
          break;
        }
        case "connect": {
          if (currentRole !== "sender") {
            ws.send(JSON.stringify({ type: "error", error: "Only sender can connect" }));
            break;
          }
          if (!roleInstance || !roleInstance.connect) {
            ws.send(JSON.stringify({ type: "error", error: "Role not configured. Please set role first." }));
            break;
          }
          const cfg = msg.config || {};
          await roleInstance.connect(cfg);
          break;
        }
        case "sendMessage": {
          if (roleInstance && roleInstance.sendMessage) {
            await roleInstance.sendMessage(msg.text || "");
          } else {
            ws.send(JSON.stringify({ type: "error", error: "Role not ready" }));
          }
          break;
        }
        case "checkHandshake": {
          if (roleInstance && roleInstance.checkHandshake) {
            const handshakeStatus = roleInstance.checkHandshake();
            ws.send(JSON.stringify({ 
              type: "handshakeStatus", 
              complete: handshakeStatus.complete,
              status: handshakeStatus.status 
            }));
          } else {
            ws.send(JSON.stringify({ 
              type: "handshakeStatus", 
              complete: false,
              status: "Role not configured" 
            }));
          }
          break;
        }
        default:
          ws.send(JSON.stringify({ type: "error", error: "Unknown command" }));
      }
    } catch (e) {
      log("ui", `WebSocket error: ${e.message}`);
      ws.send(JSON.stringify({ type: "error", error: e.message }));
    }
  });
});

server.listen(PORT, () => {
  log("app", `Server listening on http://localhost:${PORT} (local IP: ${getLocalIp()})`);
});


