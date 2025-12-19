const statusEl = document.getElementById("status");
const roleSelect = document.getElementById("role-select");
const setRoleBtn = document.getElementById("set-role-btn");
const localIpEl = document.getElementById("local-ip");
const chatLog = document.getElementById("chat-log");
const sendBtn = document.getElementById("send-btn");
const chatInput = document.getElementById("chat-input");
const discoverBtn = document.getElementById("discover-btn");
const refreshBtn = document.getElementById("refresh-btn");
const connectBtn = document.getElementById("connect-btn");
const discoverResults = document.getElementById("discover-results");

let ws;
let currentRole = null;
let handshakeComplete = false;

function logLine(text, className = "") {
  const div = document.createElement("div");
  div.textContent = text;
  if (className) div.className = className;
  chatLog.appendChild(div);
  chatLog.scrollTop = chatLog.scrollHeight;
}

// Removed updateDecryptionDisplay - receiver now uses checkboxes in receiver-security-section

function showRoleSections(role) {
  // Hide role selection section once role is set
  document.getElementById("role-section").style.display = "none";
  
  // Hide all role-specific sections first
  document.getElementById("network-section").style.display = "none";
  document.getElementById("security-section").style.display = "none";
  document.getElementById("receiver-security-section").style.display = "none";
  document.getElementById("chat-section").style.display = "none";
  document.getElementById("attacker-section").style.display = "none";
  
  // Show role-specific sections (each in its own window)
  if (role === "sender") {
    document.getElementById("network-section").style.display = "block";
    document.getElementById("security-section").style.display = "block";
    document.getElementById("chat-section").style.display = "block";
    // Show chat input for sender
    document.getElementById("chat-input-row").style.display = "flex";
    // Show Connect button for sender
    connectBtn.style.display = "inline-block";
  } else if (role === "receiver") {
    document.getElementById("network-section").style.display = "block";
    document.getElementById("receiver-security-section").style.display = "block";
    document.getElementById("chat-section").style.display = "block";
    // Hide chat input for receiver (read-only)
    document.getElementById("chat-input-row").style.display = "none";
    // Hide Connect button for receiver (it listens, doesn't connect)
    connectBtn.style.display = "none";
  } else if (role === "attacker") {
    document.getElementById("network-section").style.display = "block";
    // Attacker doesn't need security section - it just relays frames without decrypting
    document.getElementById("security-section").style.display = "none";
    document.getElementById("chat-section").style.display = "block";
    document.getElementById("attacker-section").style.display = "block";
    // Hide chat input for attacker (read-only)
    document.getElementById("chat-input-row").style.display = "none";
    // Hide Connect button for attacker
    connectBtn.style.display = "none";
  }
}

// Role selection is handled via the dropdown and setRoleBtn, no prompt needed

async function initInfo() {
  try {
    const res = await fetch("/api/info");
    const info = await res.json();
    localIpEl.textContent = info.localIp + ":" + info.defaultPort + " (TCP)";
    
    // Set default values (no restoration from localStorage)
    document.getElementById("target-port").value = info.defaultPort;
    document.getElementById("target-ip").value = "";
    document.getElementById("enc-mode").value = "0";
    document.getElementById("kx-mode").value = "psk";
    document.getElementById("psk-input").value = "";
    document.getElementById("transport").value = "tcp";
    
    // Set default values for receiver
    document.getElementById("receiver-decrypt-mode").value = "0";
    document.getElementById("receiver-kx-mode").value = "psk";
    document.getElementById("receiver-psk-input").value = "";
    document.getElementById("receiver-demo-mode").checked = false;
    
    // Hide all sections initially, show only role selection window
    document.getElementById("network-section").style.display = "none";
    document.getElementById("security-section").style.display = "none";
    document.getElementById("receiver-security-section").style.display = "none";
    document.getElementById("chat-section").style.display = "none";
    document.getElementById("attacker-section").style.display = "none";
    
    // Always show only role selection window on startup (no restoration)
    document.getElementById("role-section").style.display = "block";
    // Hide status initially when no role is set
    statusEl.style.display = "none";
  } catch (e) {
    localIpEl.textContent = "Unknown";
  }
}

function ensureWs() {
  if (ws && ws.readyState === WebSocket.OPEN) return;
  ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host);
  ws.onopen = () => {
    statusEl.textContent = "Connected to local control server";
  };
  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.type === "status") {
        statusEl.textContent = msg.status;
        // Check if handshake is complete
        if (msg.status && msg.status.toLowerCase().includes("handshake complete")) {
          handshakeComplete = true;
          logLine("✓ Handshake complete - ready to send/receive", "success");
        } else if (msg.status && msg.status.toLowerCase().includes("listening")) {
          handshakeComplete = false;
        }
      } else if (msg.type === "log") {
        logLine(msg.message);
      } else if (msg.type === "discoveryResults") {
        displayDiscoveryResults(msg.results);
      } else if (msg.type === "error") {
        statusEl.textContent = "Error: " + msg.error;
        logLine("ERROR: " + msg.error, "error");
      } else if (msg.type === "attackSuccess") {
        logLine(`⚠ ATTACK SUCCESS: ${msg.message}`, "attack-success");
      } else if (msg.type === "attackFailed") {
        logLine(`✗ ATTACK FAILED: ${msg.message}`, "attack-failed");
      } else if (msg.type === "messageSent") {
        logLine(`→ SENT: ${msg.text}`, "message-sent");
      } else if (msg.type === "messageReceived") {
        logLine(`← RECEIVED: ${msg.text}`, "message-received");
      } else if (msg.type === "handshakeStatus") {
        // Update handshake status
        handshakeComplete = msg.complete;
        if (msg.complete) {
          logLine(`✓ ${msg.status}`, "success");
          statusEl.textContent = msg.status;
        } else {
          // Only log if it's a meaningful status change
          if (msg.status && !msg.status.includes("Role not configured") && !msg.status.includes("No role selected")) {
            logLine(`⏳ ${msg.status}`, "role-selected");
          }
          // Only update status if it's not already showing a more specific message
          if (!statusEl.textContent.includes("Handshake complete") && !statusEl.textContent.includes("listening")) {
            statusEl.textContent = msg.status;
          }
        }
      }
    } catch (e) {
      console.error(e);
    }
  };
  ws.onclose = () => {
    statusEl.textContent = "Disconnected from local control server";
  };
}

setRoleBtn.onclick = () => {
  ensureWs();
  const role = roleSelect.value;
  if (!role) {
    logLine("Please select a role first", "error");
    return;
  }
  
  currentRole = role;
  handshakeComplete = false;
  
  // Show status section once role is set
  statusEl.style.display = "block";
  
  // Hide role selection and show role-specific sections
  showRoleSections(role);
  
  const targetIp = document.getElementById("target-ip").value.trim();
  const port = parseInt(document.getElementById("target-port").value, 10) || 12347;
  const transport = document.getElementById("transport").value;
  const attackMode = document.getElementById("attack-mode").value;
  const dropRate = parseInt(document.getElementById("drop-rate").value, 10) || 0;
  const delayMs = parseInt(document.getElementById("delay-ms").value, 10) || 0;
  const modifyText = document.getElementById("modify-text").value.trim();
  
  // Get config based on role
  let config = {
    targetIp,
    port,
    transport,
    attackMode,
    dropRate,
    delayMs,
    modifyText
  };
  
  if (role === "sender") {
    const encMode = parseInt(document.getElementById("enc-mode").value, 10);
    const kxMode = document.getElementById("kx-mode").value;
    const psk = document.getElementById("psk-input").value;
    const demo = document.getElementById("demo-mode").checked;
    config.encMode = encMode;
    config.kxMode = kxMode;
    config.psk = psk;
    config.demo = demo;
  } else if (role === "receiver") {
    // Get decryption mode from dropdown
    const decryptionMode = parseInt(document.getElementById("receiver-decrypt-mode").value, 10);
    const kxMode = document.getElementById("receiver-kx-mode").value;
    const psk = document.getElementById("receiver-psk-input").value;
    const demo = document.getElementById("receiver-demo-mode").checked;
    config.encMode = decryptionMode;
    config.kxMode = kxMode;
    config.psk = psk;
    config.demo = demo;
  }

  // Clear chat log when setting new role
  chatLog.innerHTML = "";
  logLine(`Setting role to: ${role}`, "role-selected");

  ws.send(
    JSON.stringify({
      type: "configureRole",
      role,
      config
    })
  );
  
  // Auto-connect sender if target IP is provided
  if (role === "sender" && targetIp) {
    // Small delay to ensure role is configured first
    setTimeout(() => {
      connectBtn.click();
    }, 100);
  }
};

connectBtn.onclick = () => {
  ensureWs();
  
  // Check role from dropdown, not just currentRole variable
  const role = roleSelect.value;
  if (role !== "sender") {
    logLine("Only sender role can connect. Please select 'Sender' role first.", "error");
    return;
  }
  
  // Update currentRole if it's not set
  if (!currentRole) {
    currentRole = role;
  }
  
  const targetIp = document.getElementById("target-ip").value.trim();
  if (!targetIp) {
    logLine("Please enter a target IP address", "error");
    return;
  }
  
  const port = parseInt(document.getElementById("target-port").value, 10) || 12347;
  const transport = document.getElementById("transport").value;
  const encMode = parseInt(document.getElementById("enc-mode").value, 10);
  const kxMode = document.getElementById("kx-mode").value;
  const psk = document.getElementById("psk-input").value;
  const demo = document.getElementById("demo-mode").checked;
  
  handshakeComplete = false;
  logLine(`Connecting to ${targetIp}:${port}...`, "role-selected");
  
  ws.send(
    JSON.stringify({
      type: "connect",
      role: "sender", // Explicitly send role
      config: {
        targetIp,
        port,
        transport,
        encMode,
        kxMode,
        psk,
        demo
      }
    })
  );
};

refreshBtn.onclick = () => {
  ensureWs();
  
  if (!currentRole) {
    logLine("Please set a role first", "error");
    return;
  }
  
  // For sender role, refresh discovery
  if (currentRole === "sender") {
    discoverResults.innerHTML = "<div style='color: #eaeaea;'>Refreshing discovery...</div>";
    const cfg = {
      port: parseInt(document.getElementById("target-port").value, 10) || 12347
    };
    ws.send(JSON.stringify({ type: "discover", config: cfg }));
  }
  
  // For all roles, check handshake status
  ws.send(JSON.stringify({ type: "checkHandshake" }));
};

sendBtn.onclick = () => {
  ensureWs();
  const text = chatInput.value;
  if (!text) return;
  
  if (currentRole !== "sender") {
    logLine("Only sender can send messages", "error");
    return;
  }
  
  if (!handshakeComplete) {
    logLine("Handshake not complete. Please wait for connection...", "error");
    return;
  }
  
  ws.send(JSON.stringify({ type: "sendMessage", text }));
  chatInput.value = "";
};

function displayDiscoveryResults(results) {
  discoverResults.innerHTML = "";
  if (!results || results.length === 0) {
    discoverResults.innerHTML = "<div style='color: #eaeaea;'>No devices found. Make sure other devices have set their roles and are on the same network.</div>";
    return;
  }
  
  const title = document.createElement("div");
  title.textContent = `Found ${results.length} device(s):`;
  title.style.marginBottom = "8px";
  title.style.fontWeight = "bold";
  title.style.color = "#eaeaea";
  discoverResults.appendChild(title);
  
  results.forEach(result => {
    // Parse result format: "role@ip:port"
    const match = result.match(/^([^@]+)@(.+):(\d+)$/);
    if (match) {
      const [, role, ip, port] = match;
      const div = document.createElement("div");
      div.style.padding = "4px";
      div.style.cursor = "pointer";
      div.style.marginBottom = "4px";
      div.style.borderBottom = "1px solid #555";
      div.style.color = "#eaeaea";
      div.onmouseover = () => { div.style.background = "#3d3d3d"; };
      div.onmouseout = () => { div.style.background = "transparent"; };
      
      const roleSpan = document.createElement("span");
      roleSpan.textContent = role.toUpperCase() + ": ";
      roleSpan.style.color = "#4a9eff";
      roleSpan.style.fontWeight = "bold";
      
      const ipSpan = document.createElement("span");
      ipSpan.textContent = ip + ":" + port;
      ipSpan.style.color = "#4caf50";
      
      div.appendChild(roleSpan);
      div.appendChild(ipSpan);
      
      div.onclick = () => {
        document.getElementById("target-ip").value = ip;
        logLine(`Selected discovered device: ${role} at ${ip}:${port}`, "success");
      };
      
      discoverResults.appendChild(div);
    } else {
      // Fallback for unexpected format
      const div = document.createElement("div");
      div.textContent = result;
      div.style.padding = "4px";
      discoverResults.appendChild(div);
    }
  });
}

discoverBtn.onclick = () => {
  ensureWs();
  discoverResults.innerHTML = "<div style='color: #eaeaea;'>Discovering on LAN...</div>";
  const cfg = {
    port: parseInt(document.getElementById("target-port").value, 10) || 12347
  };
  ws.send(JSON.stringify({ type: "discover", config: cfg }));
};

initInfo();


