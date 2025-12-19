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
  socket.bind(DISCOVERY_PORT, () => {
    socket.setBroadcast(true);
  });
  const peers = new Set();

  socket.on("message", (msg, rinfo) => {
    try {
      const obj = JSON.parse(msg.toString("utf8"));
      if (obj.magic === MAGIC) {
        // Handle probe request - respond with our presence
        if (obj.probe && currentRole && currentPort) {
          // Respond directly to the sender of the probe
          const response = Buffer.from(
            JSON.stringify({ magic: MAGIC, role: currentRole, ip: getLocalIp(), port: currentPort }),
            "utf8"
          );
          socket.send(response, 0, response.length, rinfo.port, rinfo.address, (err) => {
            if (err) {
              // Silently ignore send errors
            }
          });
        }
        // Handle presence announcement (both broadcast and direct responses)
        if (obj.ip && obj.role && !obj.probe) {
          // Use the port from the message, or rinfo.port if not provided
          const devicePort = obj.port || rinfo.port;
          const key = `${obj.role}@${rinfo.address}:${devicePort}`;
          peers.add(key);
        }
      }
    } catch {
      // ignore parse errors
    }
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
  state.socket.send(msg, 0, msg.length, DISCOVERY_PORT, "255.255.255.255");
  
  // Wait longer for responses (devices need time to respond to probe)
  await new Promise((r) => setTimeout(r, 1500));
  return Array.from(state.peers.values());
}

module.exports = {
  startDiscovery,
  stopDiscovery,
  broadcastPresence,
  sendDiscoveryPing
};


