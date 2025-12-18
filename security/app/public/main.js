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

function showRoleSections(role) {
  // Hide all role-specific sections first
  document.getElementById("network-section").style.display = "none";
  document.getElementById("security-section").style.display = "none";
  document.getElementById("chat-section").style.display = "none";
  document.getElementById("attacker-section").style.display = "none";
  
  // Show role-specific sections
  if (role === "sender") {
    document.getElementById("network-section").style.display = "block";
    document.getElementById("security-section").style.display = "block";
    document.getElementById("chat-section").style.display = "block";
  } else if (role === "receiver") {
    document.getElementById("network-section").style.display = "block";
    document.getElementById("security-section").style.display = "block";
    document.getElementById("chat-section").style.display = "block";
    // Hide chat input for receiver
    document.getElementById("chat-input-row").style.display = "none";
  } else if (role === "attacker") {
    document.getElementById("network-section").style.display = "block";
    document.getElementById("security-section").style.display = "block";
    document.getElementById("chat-section").style.display = "block";
    document.getElementById("attacker-section").style.display = "block";
    // Hide chat input for attacker
    document.getElementById("chat-input-row").style.display = "none";
  }
  
  // Always show role section
  document.getElementById("role-section").style.display = "block";
}

function promptRoleSelection() {
  const role = prompt("Please select your role:\n1. sender\n2. receiver\n3. attacker\n\nEnter the role name:", "");
  if (role && ["sender", "receiver", "attacker"].includes(role.toLowerCase())) {
    roleSelect.value = role.toLowerCase();
    currentRole = role.toLowerCase();
    showRoleSections(currentRole);
    logLine(`Role selected: ${currentRole}`, "role-selected");
    return true;
  } else if (role) {
    alert("Invalid role. Please choose: sender, receiver, or attacker");
    return promptRoleSelection();
  }
  return false;
}

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
    
    // Hide all sections initially, show only role selection
    document.getElementById("network-section").style.display = "none";
    document.getElementById("security-section").style.display = "none";
    document.getElementById("chat-section").style.display = "none";
    document.getElementById("attacker-section").style.display = "none";
    
    // Check if role was saved, otherwise prompt
    if (saved.role && ["sender", "receiver", "attacker"].includes(saved.role)) {
      roleSelect.value = saved.role;
      currentRole = saved.role;
      showRoleSections(currentRole);
      logLine(`Restored role: ${currentRole}`, "role-selected");
    } else {
      // Prompt for role selection on startup
      if (!promptRoleSelection()) {
        logLine("No role selected. Please refresh and select a role.", "error");
      }
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
    alert("Please select a role first");
    return;
  }
  
  currentRole = role;
  handshakeComplete = false;
  showRoleSections(role);
  
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

discoverBtn.onclick = () => {
  ensureWs();
  discoverResults.textContent = "Discovering on LAN...";
  ws.send(JSON.stringify({ type: "discover" }));
};

initInfo();


