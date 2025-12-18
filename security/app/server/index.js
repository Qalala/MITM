const express = require("express");
const path = require("path");
const http = require("http");
const os = require("os");
const WebSocket = require("ws");
const { log } = require("../../core/logging/logger");
const { createSender } = require("./roles/sender");
const { createReceiver } = require("./roles/receiver");
const { createAttacker } = require("./roles/attacker");
const { startDiscovery, stopDiscovery, sendDiscoveryPing } = require("./lan/discovery");

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

wss.on("connection", (ws) => {
  log("ui", "WebSocket client connected");
  ws.on("message", async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      switch (msg.type) {
        case "configureRole": {
          currentRole = msg.role;
          if (roleInstance && roleInstance.stop) {
            await roleInstance.stop();
          }
          if (!discovery) {
            discovery = startDiscovery();
          }
          const cfg = msg.config || {};
          if (currentRole === "sender") {
            roleInstance = createSender(cfg, ws);
          } else if (currentRole === "receiver") {
            roleInstance = createReceiver(cfg, ws);
          } else if (currentRole === "attacker") {
            roleInstance = createAttacker(cfg, ws);
          } else {
            throw new Error("Unknown role");
          }
          ws.send(JSON.stringify({ type: "status", status: `Role set to ${currentRole}` }));
          break;
        }
        case "discover": {
          if (!discovery) {
            discovery = startDiscovery();
          }
          const results = await sendDiscoveryPing(discovery);
          ws.send(
            JSON.stringify({
              type: "log",
              message: `Discovery results: ${results.join(", ") || "none"}`
            })
          );
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


