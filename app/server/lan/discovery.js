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
  let socketReady = false;
  
  // Bind to all interfaces
  socket.bind(DISCOVERY_PORT, "0.0.0.0", () => {
    try {
      socket.setBroadcast(true);
      // Allow reuse address to prevent "address already in use" errors
      socket.setRecvBufferSize(65536);
      socketReady = true;
    } catch (err) {
      // Ignore errors on some systems
      socketReady = true; // Still mark as ready even if options fail
    }
  });
  
  const peers = new Set();
  
  // Create state object that will be updated and referenced by the closure
  const state = {
    currentRole,
    currentPort
  };

  socket.on("message", (msg, rinfo) => {
    try {
      const obj = JSON.parse(msg.toString("utf8"));
      if (obj.magic === MAGIC) {
        // Handle probe request - respond with our presence
        if (obj.probe) {
          // Only respond if we have a role configured
          // Reference state.currentRole and state.currentPort so updates are reflected
          if (state.currentRole && state.currentPort && state.currentRole !== "unknown") {
            // Respond directly to the sender of the probe
            // Always use DISCOVERY_PORT as destination - sender should be listening on this port
            // rinfo.port might be DISCOVERY_PORT or might be the ephemeral port the probe came from
            // But we always respond to DISCOVERY_PORT since that's where the sender's socket is bound
            const response = Buffer.from(
              JSON.stringify({ magic: MAGIC, role: state.currentRole, ip: getLocalIp(), port: state.currentPort }),
              "utf8"
            );
            // Try both DISCOVERY_PORT and rinfo.port to ensure response reaches sender
            socket.send(response, 0, response.length, DISCOVERY_PORT, rinfo.address, (err) => {
              if (err) {
                // If DISCOVERY_PORT fails, try the port from rinfo
                socket.send(response, 0, response.length, rinfo.port, rinfo.address, () => {});
              }
            });
            // Also send to rinfo.port in case sender is using that port
            if (rinfo.port !== DISCOVERY_PORT) {
              socket.send(response, 0, response.length, rinfo.port, rinfo.address, () => {});
            }
          }
        }
        // Handle presence announcement (both broadcast and direct responses to probes)
        // This catches both periodic broadcasts and direct responses to probe requests
        if (obj.ip && obj.role && !obj.probe) {
          // Don't add ourselves to the peer list
          const localIp = getLocalIp();
          
          // Determine the actual peer IP address
          // For direct probe responses: rinfo.address is the responder's actual IP (most reliable)
          // For broadcasts: rinfo.address might be broadcast address, so use obj.ip from message
          let peerIp;
          if (rinfo.address === "255.255.255.255" || rinfo.address === "0.0.0.0") {
            // This is a broadcast, use IP from message
            peerIp = obj.ip;
          } else if (rinfo.address && rinfo.address !== "127.0.0.1") {
            // Direct response or unicast, use rinfo.address (the actual sender's IP) - most reliable
            peerIp = rinfo.address;
          } else {
            // Fallback to IP from message
            peerIp = obj.ip;
          }
          
          // Only add if it's not ourselves and is a valid IP
          if (peerIp && peerIp !== localIp && peerIp !== "127.0.0.1" && peerIp !== "0.0.0.0" && 
              !peerIp.startsWith("169.254.") && peerIp !== "255.255.255.255") {
            // Use the port from the message (this is the main TCP port, not discovery port)
            const devicePort = obj.port || 12347;
            const key = `${obj.role}@${peerIp}:${devicePort}`;
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

  // Return state object with socket and peers, so updates to currentRole/currentPort are reflected
  // The closure references state.currentRole and state.currentPort, so updates to the returned object
  // need to also update the internal state object
  const returnState = {
    socket,
    peers,
    get currentRole() { return state.currentRole; },
    set currentRole(val) { state.currentRole = val; },
    get currentPort() { return state.currentPort; },
    set currentPort(val) { state.currentPort = val; }
  };
  return returnState;
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
  
  // Update the state with current role/port for probe responses
  // The getter/setter will update the internal state object used by the closure
  if (state) {
    state.currentRole = role;
    state.currentPort = mainPort;
  }
}

async function sendDiscoveryPing(state) {
  if (!state || !state.socket) return [];
  
  // Wait a bit to ensure socket is bound and ready
  await new Promise((r) => setTimeout(r, 200));
  
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
  for (let i = 0; i < 3; i++) {
    await new Promise((r) => setTimeout(r, 300));
    state.socket.send(msg, 0, msg.length, DISCOVERY_PORT, "255.255.255.255", () => {});
    // Also try network broadcast
    try {
      const localIp = getLocalIp();
      const parts = localIp.split(".");
      if (parts.length === 4) {
        const networkBroadcast = `${parts[0]}.${parts[1]}.${parts[2]}.255`;
        state.socket.send(msg, 0, msg.length, DISCOVERY_PORT, networkBroadcast, () => {});
      }
    } catch {}
  }
  
  // Final wait for responses - increased wait time to ensure all responses are received
  await new Promise((r) => setTimeout(r, 1500));
  
  return Array.from(state.peers.values());
}

module.exports = {
  startDiscovery,
  stopDiscovery,
  broadcastPresence,
  sendDiscoveryPing
};


