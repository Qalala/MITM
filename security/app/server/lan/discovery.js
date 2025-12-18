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

function startDiscovery() {
  const socket = dgram.createSocket("udp4");
  socket.bind(DISCOVERY_PORT, () => {
    socket.setBroadcast(true);
  });
  const peers = new Set();

  socket.on("message", (msg, rinfo) => {
    try {
      const obj = JSON.parse(msg.toString("utf8"));
      if (obj.magic === MAGIC && obj.ip && obj.role) {
        const key = `${obj.role}@${rinfo.address}:${obj.port}`;
        peers.add(key);
      }
    } catch {
      // ignore
    }
  });

  return { socket, peers };
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
  if (!state) return;
  const msg = Buffer.from(
    JSON.stringify({ magic: MAGIC, role, ip: getLocalIp(), port: mainPort }),
    "utf8"
  );
  state.socket.send(msg, 0, msg.length, DISCOVERY_PORT, "255.255.255.255");
}

async function sendDiscoveryPing(state) {
  if (!state) return [];
  const msg = Buffer.from(
    JSON.stringify({ magic: MAGIC, probe: true, ip: getLocalIp() }),
    "utf8"
  );
  state.socket.send(msg, 0, msg.length, DISCOVERY_PORT, "255.255.255.255");
  await new Promise((r) => setTimeout(r, 500));
  return Array.from(state.peers.values());
}

module.exports = {
  startDiscovery,
  stopDiscovery,
  broadcastPresence,
  sendDiscoveryPing
};


