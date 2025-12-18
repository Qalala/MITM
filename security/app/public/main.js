const statusEl = document.getElementById("status");
const roleSelect = document.getElementById("role-select");
const setRoleBtn = document.getElementById("set-role-btn");
const localIpEl = document.getElementById("local-ip");
const chatLog = document.getElementById("chat-log");
const sendBtn = document.getElementById("send-btn");
const chatInput = document.getElementById("chat-input");
const discoverBtn = document.getElementById("discover-btn");
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
  const decryptionText = document.getElementById("decryption-mode-text");
  const encMode = parseInt(document.getElementById("enc-mode").value, 10);
  
  const modeNames = {
    0: "Plaintext (None)",
    1: "AES-GCM",
    2: "AES-CBC + HMAC-SHA256",
    3: "Diffie-Hellman"
  };
  
  decryptionText.textContent = modeNames[encMode] || "Unknown";
  decryptionDisplay.style.display = currentRole === "receiver" ? "block" : "none";
}

function showRoleSections(role) {
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
  } else if (role === "receiver") {
    document.getElementById("network-section").style.display = "block";
    document.getElementById("security-section").style.display = "block";
    document.getElementById("chat-section").style.display = "block";
    // Hide chat input for receiver (read-only)
    document.getElementById("chat-input-row").style.display = "none";
    // Show decryption mode display for receiver
    updateDecryptionDisplay();
  } else if (role === "attacker") {
    document.getElementById("network-section").style.display = "block";
    // Attacker doesn't need security section - it just relays frames without decrypting
    document.getElementById("security-section").style.display = "none";
    document.getElementById("chat-section").style.display = "block";
    document.getElementById("attacker-section").style.display = "block";
    // Hide chat input for attacker (read-only)
    document.getElementById("chat-input-row").style.display = "none";
    document.getElementById("decryption-mode-display").style.display = "none";
  }
  
  // Keep role section visible for changing roles
  document.getElementById("role-section").style.display = "block";
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
    document.getElementById("enc-mode").addEventListener("change", updateDecryptionDisplay);
    
    // Hide all sections initially, show only role selection window
    document.getElementById("network-section").style.display = "none";
    document.getElementById("security-section").style.display = "none";
    document.getElementById("chat-section").style.display = "none";
    document.getElementById("attacker-section").style.display = "none";
    
    // Check if role was saved, otherwise show only role selection
    if (saved.role && ["sender", "receiver", "attacker"].includes(saved.role)) {
      roleSelect.value = saved.role;
      currentRole = saved.role;
      showRoleSections(currentRole);
      logLine(`Restored role: ${currentRole}`, "role-selected");
    } else {
      // Show only role selection window on startup
      document.getElementById("role-section").style.display = "block";
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
    discoverResults.textContent = "No devices found. Make sure other devices have set their roles and are on the same network.";
    return;
  }
  
  const title = document.createElement("div");
  title.textContent = `Found ${results.length} device(s):`;
  title.style.marginBottom = "8px";
  title.style.fontWeight = "bold";
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
      div.style.borderBottom = "1px solid #333";
      div.onmouseover = () => { div.style.background = "#333"; };
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
  discoverResults.innerHTML = "<div>Discovering on LAN...</div>";
  ws.send(JSON.stringify({ type: "discover" }));
};

initInfo();


