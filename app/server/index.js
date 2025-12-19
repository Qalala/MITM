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
const { initPythonCrypto } = require("../../scripts/startup_init");

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
          // CRITICAL: Discovery must be started for ALL roles (sender, receiver, attacker)
          // This allows sender to discover receivers and vice versa
          if (discovery && discovery.socket) {
            // Update existing discovery with new role/port
            discovery.currentRole = currentRole;
            discovery.currentPort = port;
          } else {
            // Start fresh discovery - ensure socket is properly initialized
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
          // CRITICAL: ALL roles (including sender) must broadcast so they can be discovered
          if (currentRole && currentRole !== "unknown") {
            // Include encryption info for sender/receiver only
            let encInfo = null;
            if ((currentRole === "sender" || currentRole === "receiver") && cfg.encMode !== undefined && cfg.kxMode) {
              encInfo = { encMode: cfg.encMode, kxMode: cfg.kxMode };
              discovery.encInfo = encInfo;
            }
            broadcastPresence(discovery, currentRole, port, encInfo);
            broadcastInterval = setInterval(() => {
              if (discovery && discovery.socket) {
                const currentEncInfo = discovery.encInfo;
                broadcastPresence(discovery, currentRole, port, currentEncInfo);
              }
            }, 3000); // Broadcast every 3 seconds
          }
          
          // Do NOT auto-connect - user must click connect button after setting IP/port
          ws.send(JSON.stringify({ type: "status", status: `Role set to ${currentRole}` }));
          break;
        }
        case "discover": {
          const cfg = msg.config || {};
          const port = cfg.port || 12347;
          
          // Ensure discovery is started and properly configured
          if (!discovery || !discovery.socket) {
            discovery = startDiscovery(currentRole || "unknown", port);
          } else {
            // Update role/port if changed
            discovery.currentRole = currentRole || "unknown";
            discovery.currentPort = port;
          }
          
          // Clear previous results before new discovery
          if (discovery.peers) {
            discovery.peers.clear();
          }
          
          // Send probe and wait for responses
          // This will discover receivers and attackers on the network
          const results = await sendDiscoveryPing(discovery);
          
          // Also broadcast our own presence so others can discover us
          if (currentRole && currentRole !== "unknown") {
            broadcastPresence(discovery, currentRole, port);
          }
          
          ws.send(
            JSON.stringify({
              type: "discoveryResults",
              results: results.length > 0 ? results : []
            })
          );
          break;
        }
        case "connect": {
          // Allow role to be specified in the connect message
          const requestedRole = msg.role || currentRole;
          if (requestedRole !== "sender") {
            ws.send(JSON.stringify({ type: "error", error: "Only sender can connect. Please set role to 'Sender' first." }));
            break;
          }
          
          const cfg = msg.config || {};
          const port = cfg.port || 12347;
          
          // Ensure discovery is started for sender (needed for discovery to work)
          if (!discovery || !discovery.socket) {
            discovery = startDiscovery("sender", port);
          } else {
            // Update discovery role/port
            discovery.currentRole = "sender";
            discovery.currentPort = port;
          }
          
          // Ensure sender role is configured before connecting
          if (currentRole !== "sender" || !roleInstance) {
            // Configure sender role first
            currentRole = "sender";
            if (roleInstance && roleInstance.stop) {
              await roleInstance.stop();
            }
            
            // Stop previous broadcast interval
            if (broadcastInterval) {
              clearInterval(broadcastInterval);
              broadcastInterval = null;
            }
            
            // Start or restart discovery with sender role/port
            if (discovery && discovery.socket) {
              discovery.currentRole = "sender";
              discovery.currentPort = port;
            } else {
              discovery = startDiscovery("sender", port);
            }
            
            roleInstance = createSender(cfg, ws);
            
            // Broadcast presence so receiver can discover sender
            broadcastPresence(discovery, "sender", port);
            broadcastInterval = setInterval(() => {
              if (discovery && discovery.socket) {
                broadcastPresence(discovery, "sender", port);
              }
            }, 3000);
          }
          
          if (!roleInstance || !roleInstance.connect) {
            ws.send(JSON.stringify({ type: "error", error: "Role not ready. Please set role to 'Sender' first." }));
            break;
          }
          
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
        case "updateSecurityConfig": {
          if (!currentRole) {
            ws.send(JSON.stringify({ type: "error", error: "No role selected. Please set a role first." }));
            break;
          }
          
          if (currentRole !== msg.role) {
            ws.send(JSON.stringify({ type: "error", error: "Role mismatch. Please set the correct role first." }));
            break;
          }
          
          const cfg = msg.config || {};
          
          // Update encryption info in discovery for broadcasting (sender/receiver only)
          if ((currentRole === "sender" || currentRole === "receiver") && discovery && cfg.encMode !== undefined && cfg.kxMode) {
            discovery.encInfo = { encMode: cfg.encMode, kxMode: cfg.kxMode };
            // Broadcast encryption change immediately (only to sender/receiver, not attacker)
            const port = cfg.port || 12347;
            broadcastPresence(discovery, currentRole, port, discovery.encInfo);
          }
          
          // Update the role instance with new security config
          if (roleInstance && roleInstance.updateSecurityConfig) {
            await roleInstance.updateSecurityConfig(cfg);
            ws.send(JSON.stringify({ type: "status", status: `Security settings updated for ${currentRole}` }));
          } else if (roleInstance) {
            // If updateSecurityConfig is not available, recreate the instance with new config
            // This is a fallback for roles that don't support dynamic updates
            if (roleInstance.stop) {
              await roleInstance.stop();
            }
            
            // Recreate with new config
            if (currentRole === "sender") {
              roleInstance = createSender(cfg, ws);
            } else if (currentRole === "receiver") {
              roleInstance = createReceiver(cfg, ws);
            } else if (currentRole === "attacker") {
              roleInstance = createAttacker(cfg, ws);
            }
            
            ws.send(JSON.stringify({ type: "status", status: `Security settings updated for ${currentRole}` }));
          } else {
            ws.send(JSON.stringify({ type: "error", error: "Role instance not available" }));
          }
          break;
        }
        case "startAttack": {
          if (currentRole !== "attacker") {
            ws.send(JSON.stringify({ type: "error", error: "Only attacker role can start attacks" }));
            break;
          }
          
          if (!roleInstance) {
            ws.send(JSON.stringify({ type: "error", error: "Attacker role not configured. Please set role to 'Attacker' first." }));
            break;
          }
          
          const cfg = msg.config || {};
          if (roleInstance && roleInstance.startAttack) {
            await roleInstance.startAttack(cfg);
          } else {
            ws.send(JSON.stringify({ type: "error", error: "Attack functionality not available" }));
          }
          break;
        }
        case "updateAttackConfig": {
          if (currentRole !== "attacker") {
            ws.send(JSON.stringify({ type: "error", error: "Only attacker role can update attack config" }));
            break;
          }
          
          if (!roleInstance) {
            ws.send(JSON.stringify({ type: "error", error: "Attacker role not configured" }));
            break;
          }
          
          const cfg = msg.config || {};
          if (roleInstance && roleInstance.updateAttackConfig) {
            await roleInstance.updateAttackConfig(cfg);
            ws.send(JSON.stringify({ type: "status", status: "Attack configuration updated" }));
          } else {
            ws.send(JSON.stringify({ type: "error", error: "Attack config update not available" }));
          }
          break;
        }
        case "checkHandshake": {
          if (!currentRole) {
            ws.send(JSON.stringify({ 
              type: "handshakeStatus", 
              complete: false,
              status: "No role selected" 
            }));
          } else if (roleInstance && roleInstance.checkHandshake) {
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
              status: `Role "${currentRole}" configured, waiting for connection...` 
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
  const localIp = getLocalIp();
  log("app", `Server listening on http://localhost:${PORT} (local IP: ${localIp})`);
  
  // Initialize Python crypto utilities
  try {
    initPythonCrypto();
  } catch (err) {
    log("app", `NOTE: Python crypto initialization skipped: ${err.message}`);
  }
});


