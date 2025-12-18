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

function updateDecryptionDisplay() {
  const decryptionDisplay = document.getElementById("decryption-mode-display");
  const decryptionMethodsList = document.getElementById("decryption-methods-list");
  
  if (currentRole !== "receiver") {
    decryptionDisplay.style.display = "none";
    return;
  }
  
  decryptionDisplay.style.display = "block";
  
  // Define decryption methods and which encryption they decrypt
  const decryptionMethods = [
    { name: "Plaintext Decryption", decrypts: ["0 - None (Plaintext)"] },
    { name: "AES-GCM Decryption", decrypts: ["1 - AES-GCM"] },
    { name: "AES-CBC + HMAC-SHA256 Decryption", decrypts: ["2 - AES-CBC + HMAC-SHA256"] },
    { name: "Diffie-Hellman Decryption", decrypts: ["3 - Diffie-Hellman (demo)"] }
  ];
  
  decryptionMethodsList.innerHTML = "";
  decryptionMethods.forEach(method => {
    const div = document.createElement("div");
    div.style.marginBottom = "4px";
    div.style.padding = "4px";
    div.style.background = "#3d3d3d";
    div.style.borderRadius = "4px";
    div.innerHTML = `<strong>${method.name}</strong> <span style="color: #9e9e9e;">(decrypts: ${method.decrypts.join(", ")})</span>`;
    decryptionMethodsList.appendChild(div);
  });
}

function showRoleSections(role) {
  // Hide role selection section once role is set
  document.getElementById("role-section").style.display = "none";
  
  // Hide all role-specific sections first
  document.getElementById("network-section").style.display = "none";
  document.getElementById("security-section").style.display = "none";
  document.getElementById("chat-section").style.display = "none";
  document.getElementById("attacker-section").style.display = "none";
  
  // Show role-specific sections (each in its own window)
  if (role === "sender") {
    document.getElementById("network-section").style.display = "block";
    document.getElementById("security-section").style.display = "block";
    document.getElementById("chat-section").style.display = "block";
    // Show chat input for sender
    document.getElementById("chat-input-row").style.display = "flex";
    document.getElementById("decryption-mode-display").style.display = "none";
    // Show Connect button for sender
    connectBtn.style.display = "inline-block";
  } else if (role === "receiver") {
    document.getElementById("network-section").style.display = "block";
    document.getElementById("security-section").style.display = "block";
    document.getElementById("chat-section").style.display = "block";
    // Hide chat input for receiver (read-only)
    document.getElementById("chat-input-row").style.display = "none";
    // Show decryption mode display for receiver
    updateDecryptionDisplay();
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
    document.getElementById("decryption-mode-display").style.display = "none";
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
    const saved = JSON.parse(localStorage.getItem("lanSecureChatConfig") || "{}");
    document.getElementById("target-port").value = saved.port || info.defaultPort;
    document.getElementById("target-ip").value = saved.targetIp || "";
    document.getElementById("enc-mode").value = saved.encMode ?? "0";
    document.getElementById("kx-mode").value = saved.kxMode || "psk";
    document.getElementById("psk-input").value = saved.psk || "";
    document.getElementById("transport").value = saved.transport || "tcp";
    
    // Set up encryption mode change listener for decryption display
    document.getElementById("enc-mode").addEventListener("change", () => {
      updateDecryptionDisplay();
      // Also update role config if receiver is active
      if (currentRole === "receiver") {
        setRoleBtn.click();
      }
    });
    
    // Hide all sections initially, show only role selection window
    document.getElementById("network-section").style.display = "none";
    document.getElementById("security-section").style.display = "none";
    document.getElementById("chat-section").style.display = "none";
    document.getElementById("attacker-section").style.display = "none";
    
    // Check if role was saved, otherwise show only role selection
    if (saved.role && ["sender", "receiver", "attacker"].includes(saved.role)) {
      roleSelect.value = saved.role;
      currentRole = saved.role;
      // Show status section when role is restored
      statusEl.style.display = "block";
      showRoleSections(currentRole);
      logLine(`Restored role: ${currentRole}`, "role-selected");
    } else {
      // Show only role selection window on startup
      document.getElementById("role-section").style.display = "block";
      // Hide status initially when no role is set
      statusEl.style.display = "none";
    }
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
          logLine(`⏳ ${msg.status}`, "role-selected");
          // Only update status if it's not already showing a more specific message
          if (!statusEl.textContent.includes("Handshake complete")) {
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
  
  // Update decryption display when role changes
  if (role === "receiver") {
    updateDecryptionDisplay();
  }
  
  const targetIp = document.getElementById("target-ip").value.trim();
  const port = parseInt(document.getElementById("target-port").value, 10) || 12347;
  const transport = document.getElementById("transport").value;
  const encMode = parseInt(document.getElementById("enc-mode").value, 10);
  const kxMode = document.getElementById("kx-mode").value;
  const psk = document.getElementById("psk-input").value;
  const demo = document.getElementById("demo-mode").checked;
  const attackMode = document.getElementById("attack-mode").value;
  const dropRate = parseInt(document.getElementById("drop-rate").value, 10) || 0;
  const delayMs = parseInt(document.getElementById("delay-ms").value, 10) || 0;
  const modifyText = document.getElementById("modify-text").value;

  localStorage.setItem(
    "lanSecureChatConfig",
    JSON.stringify({ targetIp, port, transport, encMode, kxMode, psk, role })
  );

  // Clear chat log when setting new role
  chatLog.innerHTML = "";
  logLine(`Setting role to: ${role}`, "role-selected");

  ws.send(
    JSON.stringify({
      type: "configureRole",
      role,
      config: {
        targetIp,
        port,
        transport,
        encMode,
        kxMode,
        psk,
        demo,
        attackMode,
        dropRate,
        delayMs,
        modifyText
      }
    })
  );
};

connectBtn.onclick = () => {
  ensureWs();
  if (currentRole !== "sender") {
    logLine("Only sender can connect", "error");
    return;
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


