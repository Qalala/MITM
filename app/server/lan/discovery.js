const dgram = require("dgram");
const os = require("os");

const DISCOVERY_PORT = 41234;
const MAGIC = "LAN_SECURE_CHAT_DISCOVERY_V1";

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

function startDiscovery(currentRole, currentPort) {
  const socket = dgram.createSocket("udp4");
  
  // Bind to all interfaces
  socket.bind(DISCOVERY_PORT, () => {
    try {
      socket.setBroadcast(true);
      // Allow reuse address to prevent "address already in use" errors
      socket.setRecvBufferSize(65536);
    } catch (err) {
      // Ignore errors on some systems
    }
  });
  
  const peers = new Set();

  socket.on("message", (msg, rinfo) => {
    try {
      const obj = JSON.parse(msg.toString("utf8"));
      if (obj.magic === MAGIC) {
        // Handle probe request - respond with our presence
        if (obj.probe) {
          // Only respond if we have a role configured
          if (currentRole && currentPort && currentRole !== "unknown") {
            // Respond directly to the sender of the probe
            const response = Buffer.from(
              JSON.stringify({ magic: MAGIC, role: currentRole, ip: getLocalIp(), port: currentPort }),
              "utf8"
            );
            socket.send(response, 0, response.length, rinfo.port, rinfo.address, (err) => {
              if (err) {
                // Silently ignore send errors (common on some networks)
              }
            });
          }
        }
        // Handle presence announcement (both broadcast and direct responses)
        if (obj.ip && obj.role && !obj.probe) {
          // Don't add ourselves to the peer list
          const localIp = getLocalIp();
          if (rinfo.address !== localIp && rinfo.address !== "127.0.0.1") {
            // Use the port from the message, or currentPort if not provided
            const devicePort = obj.port || currentPort || 12347;
            const key = `${obj.role}@${rinfo.address}:${devicePort}`;
            peers.add(key);
          }
        }
      }
    } catch (e) {
      // ignore parse errors
    }
  });
  
  socket.on("error", (err) => {
    // Silently handle errors (common on some networks)
  });

  return { socket, peers, currentRole, currentPort };
}

function stopDiscovery(state) {
  if (!state) return;
  try {
    state.socket.close();
  } catch {
    // ignore
  }
}

function broadcastPresence(state, role, mainPort) {
  if (!state || !state.socket) return;
  const msg = Buffer.from(
    JSON.stringify({ magic: MAGIC, role, ip: getLocalIp(), port: mainPort }),
    "utf8"
  );
  state.socket.send(msg, 0, msg.length, DISCOVERY_PORT, "255.255.255.255", (err) => {
    if (err) {
      // Silently ignore broadcast errors (may fail on some networks)
    }
  });
  
  // Also update the state with current role/port for probe responses
  if (state) {
    state.currentRole = role;
    state.currentPort = mainPort;
  }
}

async function sendDiscoveryPing(state) {
  if (!state || !state.socket) return [];
  
  // Clear previous results
  if (state.peers) {
    state.peers.clear();
  }
  
  const msg = Buffer.from(
    JSON.stringify({ magic: MAGIC, probe: true, ip: getLocalIp() }),
    "utf8"
  );
  
  // Send probe to broadcast address
  state.socket.send(msg, 0, msg.length, DISCOVERY_PORT, "255.255.255.255", (err) => {
    if (err) {
      // Silently ignore - some networks don't allow broadcast
    }
  });
  
  // Also try sending to common network broadcast addresses
  // This helps on networks where 255.255.255.255 is blocked
  try {
    const localIp = getLocalIp();
    const parts = localIp.split(".");
    if (parts.length === 4) {
      const networkBroadcast = `${parts[0]}.${parts[1]}.${parts[2]}.255`;
      state.socket.send(msg, 0, msg.length, DISCOVERY_PORT, networkBroadcast, () => {});
    }
  } catch {
    // Ignore errors
  }
  
  // Wait longer for responses (devices need time to respond to probe)
  // Send multiple probes to increase chance of discovery
  for (let i = 0; i < 2; i++) {
    await new Promise((r) => setTimeout(r, 500));
    state.socket.send(msg, 0, msg.length, DISCOVERY_PORT, "255.255.255.255", () => {});
  }
  
  // Final wait for responses
  await new Promise((r) => setTimeout(r, 1000));
  
  return Array.from(state.peers.values());
}

module.exports = {
  startDiscovery,
  stopDiscovery,
  broadcastPresence,
  sendDiscoveryPing
};


