const statusEl = document.getElementById("status");
const roleSelect = document.getElementById("role-select");
const setRoleBtn = document.getElementById("set-role-btn");
const localIpEl = document.getElementById("local-ip");
const chatLog = document.getElementById("chat-log");
const sendBtn = document.getElementById("send-btn");
const chatInput = document.getElementById("chat-input");
const discoverBtn = document.getElementById("discover-btn");
const refreshBtn = document.getElementById("refresh-btn");
const connectBtn = document.getElementById("connect-btn"); // Button removed from UI but kept for compatibility
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
    const targetPort = parseInt(document.getElementById("target-port")?.value || info.defaultPort, 10);
    localIpEl.textContent = info.localIp + ":" + targetPort + " (TCP)";
    
    // Set default values (no restoration from localStorage)
    document.getElementById("target-port").value = info.defaultPort;
    
    // Update local IP display when port changes
    const targetPortInput = document.getElementById("target-port");
    if (targetPortInput) {
      targetPortInput.addEventListener("input", () => {
        const port = parseInt(targetPortInput.value, 10) || info.defaultPort;
        localIpEl.textContent = info.localIp + ":" + port + " (TCP)";
      });
    }
    
    // Update local port display when target IP changes (for all roles)
    const targetIpInput = document.getElementById("target-ip");
    if (targetIpInput) {
      targetIpInput.addEventListener("input", () => {
        const port = parseInt(targetPortInput?.value || info.defaultPort, 10);
        localIpEl.textContent = info.localIp + ":" + port + " (TCP)";
        updateTargetDisplay();
      });
    }
    
    // Update target display when port changes
    if (targetPortInput) {
      targetPortInput.addEventListener("input", () => {
        updateTargetDisplay();
      });
    }
    
    // Initial target display update
    updateTargetDisplay();
    
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
        // Check if handshake is complete - but don't override handshakeStatus messages
        if (msg.status && msg.status.toLowerCase().includes("handshake complete") && !handshakeComplete) {
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
        addAttackLog(`✓ SUCCESS: ${msg.message}`, "success");
      } else if (msg.type === "attackFailed") {
        logLine(`✗ ATTACK FAILED: ${msg.message}`, "attack-failed");
        addAttackLog(`✗ FAILED: ${msg.message}`, "failed");
      } else if (msg.type === "attackLog") {
        addAttackLog(msg.message, msg.level || "info");
      } else if (msg.type === "messageSent") {
        if (msg.encrypted && msg.ciphertext) {
          logLine(`→ SENT (ciphertext): ${msg.ciphertext}`, "message-sent");
          logLine(`→ SENT (plaintext): ${msg.text}`, "message-sent");
        } else {
          logLine(`→ SENT: ${msg.text}`, "message-sent");
        }
      } else if (msg.type === "messageReceived") {
        if (msg.encrypted && msg.ciphertext) {
          logLine(`← RECEIVED (ciphertext): ${msg.ciphertext}`, "message-received");
          logLine(`← RECEIVED (plaintext): ${msg.text}`, "message-received");
        } else {
          logLine(`← RECEIVED: ${msg.text}`, "message-received");
        }
      } else if (msg.type === "handshakeStatus") {
        // Update handshake status - this is the authoritative source
        const wasComplete = handshakeComplete;
        handshakeComplete = msg.complete;
        
        if (msg.complete) {
          if (!wasComplete) {
            // Only log if this is a new completion
            logLine(`✓ ${msg.status}`, "success");
            logLine("✓ Handshake complete - connection established", "success");
          }
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

setRoleBtn.onclick = async () => {
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
    const encModeStr = document.getElementById("enc-mode").value;
    const encMode = parseInt(encModeStr, 10);
    if (isNaN(encMode) || encMode < 0 || encMode > 3) {
      logLine(`Invalid encryption mode: ${encModeStr}. Please select a valid mode (0-3).`, "error");
      return;
    }
    const kxMode = document.getElementById("kx-mode").value;
    const psk = document.getElementById("psk-input").value;
    const demo = document.getElementById("demo-mode").checked;
    config.encMode = encMode;
    config.kxMode = kxMode;
    config.psk = psk;
    config.demo = demo;
    logLine(`Sender configured: Encryption Mode=${encMode}, KX Mode=${kxMode}`, "role-selected");
  } else if (role === "receiver") {
    // Get decryption mode from dropdown
    const decryptionModeStr = document.getElementById("receiver-decrypt-mode").value;
    const decryptionMode = parseInt(decryptionModeStr, 10);
    if (isNaN(decryptionMode) || decryptionMode < 0 || decryptionMode > 3) {
      logLine(`Invalid decryption mode: ${decryptionModeStr}. Please select a valid mode (0-3).`, "error");
      return;
    }
    const kxMode = document.getElementById("receiver-kx-mode").value;
    const psk = document.getElementById("receiver-psk-input").value;
    const demo = document.getElementById("receiver-demo-mode").checked;
    config.encMode = decryptionMode;
    config.kxMode = kxMode;
    config.psk = psk;
    config.demo = demo;
    logLine(`Receiver configured: Decryption Mode=${decryptionMode}, KX Mode=${kxMode}`, "role-selected");
    logLine(`⚠ IMPORTANT: Receiver will only accept connections from senders using Encryption Mode ${decryptionMode}`, "role-selected");
  }

  // Clear chat log when setting new role
  chatLog.innerHTML = "";
  logLine(`Setting role to: ${role}`, "role-selected");
  
  // Update local port display to show the port being used
  const res = await fetch("/api/info");
  const info = await res.json();
  localIpEl.textContent = info.localIp + ":" + port + " (TCP)";

  ws.send(
    JSON.stringify({
      type: "configureRole",
      role,
      config
    })
  );
  
  // Sender will auto-connect on the server side if target IP is provided or discovered
};

connectBtn.onclick = async () => {
  ensureWs();
  
  // Check role from dropdown, not just currentRole variable
  const role = roleSelect.value;
  if (role !== "sender") {
    logLine("Only sender role can connect. Please select 'Sender' role first.", "error");
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
  
  // Validate encryption mode
  if (isNaN(encMode) || encMode < 0 || encMode > 3) {
    logLine(`Invalid encryption mode: ${encMode}. Please select a valid mode (0-3).`, "error");
    return;
  }
  
  // If sender role hasn't been set yet, or if current role is different, set it first
  if (currentRole !== "sender") {
    logLine("Setting sender role with current configuration...", "role-selected");
    currentRole = "sender";
    handshakeComplete = false;
    
    // Show status section
    statusEl.style.display = "block";
    
    // Show role-specific sections
    showRoleSections("sender");
    
    // Get all config
    const config = {
      targetIp,
      port,
      transport,
      encMode,
      kxMode,
      psk,
      demo
    };
    
    logLine(`Sender configured: Encryption Mode=${encMode}, KX Mode=${kxMode}`, "role-selected");
    
    // Send configureRole first
    await new Promise((resolve) => {
      ws.send(
        JSON.stringify({
          type: "configureRole",
          role: "sender",
          config
        })
      );
      // Small delay to ensure role is configured
      setTimeout(resolve, 100);
    });
  }
  
  handshakeComplete = false;
  logLine(`Connecting to ${targetIp}:${port}...`, "role-selected");
  logLine(`Using Encryption Mode=${encMode}, KX Mode=${kxMode}`, "role-selected");
  
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
  
  // Send message - server will validate handshake status
  // If handshake is not complete, server will return an error message
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

  // For attacker role, also update the attacker targets list
  const attackerTargets = document.getElementById("attacker-targets");
  if (currentRole === "attacker" && attackerTargets && results.length > 0) {
    attackerTargets.innerHTML = "";
    const attackerTitle = document.createElement("div");
    attackerTitle.textContent = `Found ${results.length} device(s):`;
    attackerTitle.style.marginBottom = "8px";
    attackerTitle.style.fontWeight = "bold";
    attackerTitle.style.color = "#ff6b6b";
    attackerTargets.appendChild(attackerTitle);
  }

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
      
      div.onclick = async () => {
        document.getElementById("target-ip").value = ip;
        document.getElementById("target-port").value = port;
        // Update local port display
        try {
          const res = await fetch("/api/info");
          const info = await res.json();
          localIpEl.textContent = info.localIp + ":" + port + " (TCP)";
        } catch (e) {
          // Ignore errors
        }
        
        const currentRole = roleSelect.value;
        if (currentRole === "sender") {
          logLine(`Selected discovered device: ${role} at ${ip}:${port}`, "success");
          logLine("Click 'Connect' button to connect to this device", "role-selected");
          logLine("⚠ Ensure your encryption mode matches the receiver's decryption mode", "role-selected");
        } else if (currentRole === "receiver") {
          logLine(`Receiver configured to accept connections from: ${role} at ${ip}:${port}`, "success");
          logLine("Receiver is listening and ready to accept connections", "role-selected");
          logLine("⚠ Ensure your decryption mode matches the sender's encryption mode", "role-selected");
          // Update status to show receiver is ready
          statusEl.textContent = `Receiver listening - will accept from ${ip}:${port}`;
        } else if (currentRole === "attacker") {
          // For attacker, set target IP to the discovered device
          logLine(`Attacker target set to: ${role} at ${ip}:${port}`, "success");
          logLine("Attacker will intercept connections to this target", "role-selected");
          // Update attacker UI
          if (role === "sender") {
            document.getElementById("attacker-sender-ip").value = ip;
          } else if (role === "receiver") {
            document.getElementById("attacker-receiver-ip").value = ip;
          }
          // Update status
          statusEl.textContent = `Attacker will intercept: ${role} at ${ip}:${port}`;
          updateTargetDisplay();
        } else {
          logLine(`Selected discovered device: ${role} at ${ip}:${port}`, "success");
        }
      };
      
      discoverResults.appendChild(div);
      
      // Also add to attacker targets list
      if (currentRole === "attacker" && attackerTargets) {
        const attackerDiv = document.createElement("div");
        attackerDiv.style.padding = "4px";
        attackerDiv.style.cursor = "pointer";
        attackerDiv.style.marginBottom = "4px";
        attackerDiv.style.borderBottom = "1px solid #555";
        attackerDiv.style.color = "#eaeaea";
        attackerDiv.onmouseover = () => { attackerDiv.style.background = "#3d3d3d"; };
        attackerDiv.onmouseout = () => { attackerDiv.style.background = "transparent"; };
        
        const attackerRoleSpan = document.createElement("span");
        attackerRoleSpan.textContent = role.toUpperCase() + ": ";
        attackerRoleSpan.style.color = role === "sender" ? "#4a9eff" : (role === "receiver" ? "#4caf50" : "#ff6b6b");
        attackerRoleSpan.style.fontWeight = "bold";
        
        const attackerIpSpan = document.createElement("span");
        attackerIpSpan.textContent = ip + ":" + port;
        attackerIpSpan.style.color = "#eaeaea";
        
        attackerDiv.appendChild(attackerRoleSpan);
        attackerDiv.appendChild(attackerIpSpan);
        
        attackerDiv.onclick = () => {
          if (role === "sender") {
            document.getElementById("attacker-sender-ip").value = ip;
            logLine(`Selected sender target: ${ip}:${port}`, "success");
          } else if (role === "receiver") {
            document.getElementById("attacker-receiver-ip").value = ip;
            logLine(`Selected receiver target: ${ip}:${port}`, "success");
          }
        };
        
        attackerTargets.appendChild(attackerDiv);
      }
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


// Function to update security configuration when settings change
function updateSecurityConfig() {
  if (!currentRole || !ws || ws.readyState !== WebSocket.OPEN) {
    return; // Only update if role is set and websocket is open
  }
  
  ensureWs();
  
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
  
  if (currentRole === "sender") {
    const encModeStr = document.getElementById("enc-mode").value;
    const encMode = parseInt(encModeStr, 10);
    if (isNaN(encMode) || encMode < 0 || encMode > 3) {
      return; // Invalid mode, don't send update
    }
    const kxMode = document.getElementById("kx-mode").value;
    const psk = document.getElementById("psk-input").value;
    const demo = document.getElementById("demo-mode").checked;
    config.encMode = encMode;
    config.kxMode = kxMode;
    config.psk = psk;
    config.demo = demo;
  } else if (currentRole === "receiver") {
    const decryptionModeStr = document.getElementById("receiver-decrypt-mode").value;
    const decryptionMode = parseInt(decryptionModeStr, 10);
    if (isNaN(decryptionMode) || decryptionMode < 0 || decryptionMode > 3) {
      return; // Invalid mode, don't send update
    }
    const kxMode = document.getElementById("receiver-kx-mode").value;
    const psk = document.getElementById("receiver-psk-input").value;
    const demo = document.getElementById("receiver-demo-mode").checked;
    config.encMode = decryptionMode;
    config.kxMode = kxMode;
    config.psk = psk;
    config.demo = demo;
  }
  
  // Send update to server
  ws.send(
    JSON.stringify({
      type: "updateSecurityConfig",
      role: currentRole,
      config
    })
  );
}

// Add event listeners to security settings inputs
function setupSecurityListeners() {
  // Sender security settings
  const senderEncMode = document.getElementById("enc-mode");
  const senderKxMode = document.getElementById("kx-mode");
  const senderPsk = document.getElementById("psk-input");
  const senderDemo = document.getElementById("demo-mode");
  
  // Initial PSK indicator update and field visibility
  updatePskRequiredIndicator();
  
  if (senderDemo) {
    senderDemo.addEventListener("change", () => {
      if (currentRole === "sender") {
        updateSecurityConfig();
      }
    });
  }
  
  // Receiver security settings
  const receiverDecryptMode = document.getElementById("receiver-decrypt-mode");
  const receiverKxMode = document.getElementById("receiver-kx-mode");
  const receiverPsk = document.getElementById("receiver-psk-input");
  const receiverDemo = document.getElementById("receiver-demo-mode");
  
  if (receiverDecryptMode) {
    receiverDecryptMode.addEventListener("change", () => {
      updatePskRequiredIndicator();
      if (currentRole === "receiver") {
        updateSecurityConfig();
        logLine(`Decryption mode changed to: ${receiverDecryptMode.value}`, "role-selected");
      }
    });
  }
  
  if (receiverKxMode) {
    receiverKxMode.addEventListener("change", () => {
      updatePskRequiredIndicator();
      if (currentRole === "receiver") {
        updateSecurityConfig();
        logLine(`Key exchange mode changed to: ${receiverKxMode.value}`, "role-selected");
      }
    });
  }
  
  if (receiverPsk) {
    receiverPsk.addEventListener("input", () => {
      updatePskRequiredIndicator(); // Update indicator when PSK changes
      if (currentRole === "receiver") {
        // Debounce PSK updates to avoid too many messages
        clearTimeout(receiverPsk.updateTimeout);
        receiverPsk.updateTimeout = setTimeout(() => {
          updateSecurityConfig();
        }, 500);
      }
    });
  }
  
  // Add listeners for encryption mode and KX mode changes to update PSK indicator
  if (senderEncMode) {
    senderEncMode.addEventListener("change", () => {
      updatePskRequiredIndicator();
      if (currentRole === "sender") {
        updateSecurityConfig();
        logLine(`Encryption mode changed to: ${senderEncMode.value}`, "role-selected");
      }
    });
  }
  
  if (senderKxMode) {
    senderKxMode.addEventListener("change", () => {
      updatePskRequiredIndicator();
      if (currentRole === "sender") {
        updateSecurityConfig();
        logLine(`Key exchange mode changed to: ${senderKxMode.value}`, "role-selected");
      }
    });
  }
  
  if (senderPsk) {
    senderPsk.addEventListener("input", () => {
      updatePskRequiredIndicator(); // Update indicator when PSK changes
      if (currentRole === "sender") {
        // Debounce PSK updates to avoid too many messages
        clearTimeout(senderPsk.updateTimeout);
        senderPsk.updateTimeout = setTimeout(() => {
          updateSecurityConfig();
        }, 500);
      }
    });
  }
  
  if (receiverDecryptMode) {
    receiverDecryptMode.addEventListener("change", () => {
      updatePskRequiredIndicator();
      if (currentRole === "receiver") {
        updateSecurityConfig();
        logLine(`Decryption mode changed to: ${receiverDecryptMode.value}`, "role-selected");
      }
    });
  }
  
  if (receiverKxMode) {
    receiverKxMode.addEventListener("change", () => {
      updatePskRequiredIndicator();
      if (currentRole === "receiver") {
        updateSecurityConfig();
        logLine(`Key exchange mode changed to: ${receiverKxMode.value}`, "role-selected");
      }
    });
  }
  
  if (receiverDemo) {
    receiverDemo.addEventListener("change", () => {
      if (currentRole === "receiver") {
        updateSecurityConfig();
      }
    });
  }
}

initInfo();
// Initialize PSK indicator on page load
updatePskRequiredIndicator();
// Function to add attack log entry
function addAttackLog(message, level = "info") {
  const attackLogContent = document.getElementById("attack-log-content");
  if (!attackLogContent) return;
  
  const entry = document.createElement("div");
  entry.style.marginBottom = "4px";
  entry.style.padding = "4px";
  entry.style.borderLeft = "3px solid";
  
  if (level === "success") {
    entry.style.borderLeftColor = "#4caf50";
    entry.style.color = "#4caf50";
  } else if (level === "failed") {
    entry.style.borderLeftColor = "#f44336";
    entry.style.color = "#f44336";
  } else if (level === "warning") {
    entry.style.borderLeftColor = "#ff9800";
    entry.style.color = "#ff9800";
  } else {
    entry.style.borderLeftColor = "#9e9e9e";
    entry.style.color = "#9e9e9e";
  }
  
  const timestamp = new Date().toLocaleTimeString();
  entry.textContent = `[${timestamp}] ${message}`;
  attackLogContent.appendChild(entry);
  attackLogContent.scrollTop = attackLogContent.scrollHeight;
}

// Function to update target IP/port display
function updateTargetDisplay() {
  const targetInfo = document.getElementById("target-info");
  const targetDisplay = document.getElementById("target-display");
  if (!targetInfo || !targetDisplay) return;
  
  const targetIp = document.getElementById("target-ip")?.value.trim() || "";
  const targetPort = document.getElementById("target-port")?.value.trim() || "";
  
  // For attacker, also check attacker-specific IPs
  let displayText = "";
  if (currentRole === "attacker") {
    const senderIp = document.getElementById("attacker-sender-ip")?.value.trim() || "";
    const receiverIp = document.getElementById("attacker-receiver-ip")?.value.trim() || "";
    
    if (senderIp && receiverIp) {
      displayText = `Sender: ${senderIp}:${targetPort} → Receiver: ${receiverIp}:${targetPort}`;
    } else if (receiverIp) {
      displayText = `Receiver: ${receiverIp}:${targetPort}`;
    } else if (senderIp) {
      displayText = `Sender: ${senderIp}:${targetPort}`;
    } else if (targetIp) {
      displayText = `${targetIp}:${targetPort}`;
    } else {
      displayText = "Not set";
    }
  } else {
    if (targetIp && targetPort) {
      displayText = `${targetIp}:${targetPort}`;
    } else {
      displayText = "Not set";
    }
  }
  
  targetDisplay.textContent = displayText;
  targetInfo.style.display = displayText !== "Not set" ? "block" : "none";
}

// Function to update PSK required indicator and show/hide fields based on encryption mode
function updatePskRequiredIndicator() {
  const senderEncMode = document.getElementById("enc-mode");
  const senderKxMode = document.getElementById("kx-mode");
  const senderKxModeLabel = senderKxMode ? senderKxMode.closest("label") : null;
  const senderPskLabel = document.getElementById("psk-input") ? document.getElementById("psk-input").closest("label") : null;
  const senderPskIndicator = document.getElementById("psk-required-indicator");
  const senderPskInput = document.getElementById("psk-input");
  
  const receiverEncMode = document.getElementById("receiver-decrypt-mode");
  const receiverKxMode = document.getElementById("receiver-kx-mode");
  const receiverKxModeLabel = receiverKxMode ? receiverKxMode.closest("label") : null;
  const receiverPskLabel = document.getElementById("receiver-psk-input") ? document.getElementById("receiver-psk-input").closest("label") : null;
  const receiverPskIndicator = document.getElementById("receiver-psk-required-indicator");
  const receiverPskInput = document.getElementById("receiver-psk-input");
  
  // Update sender fields visibility and requirements
  if (senderEncMode) {
    const encMode = parseInt(senderEncMode.value, 10);
    const isPlaintext = encMode === 0;
    
    // Hide/show key exchange and PSK fields based on encryption mode
    if (senderKxModeLabel) {
      senderKxModeLabel.style.display = isPlaintext ? "none" : "block";
    }
    if (senderPskLabel) {
      senderPskLabel.style.display = isPlaintext ? "none" : "block";
    }
    
    if (!isPlaintext && senderKxMode && senderPskIndicator) {
      const kxMode = senderKxMode.value;
      const isRequired = kxMode === "psk"; // Required for PSK key exchange with encrypted modes
      
      if (isRequired) {
        senderPskIndicator.style.display = "inline";
        senderPskIndicator.textContent = "⚠ REQUIRED for PSK key exchange";
        if (senderPskInput) {
          senderPskInput.required = true;
          senderPskInput.style.borderColor = senderPskInput.value ? "" : "#ff6b6b";
        }
      } else {
        senderPskIndicator.style.display = "none";
        if (senderPskInput) {
          senderPskInput.required = false;
          senderPskInput.style.borderColor = "";
        }
      }
    } else {
      if (senderPskIndicator) {
        senderPskIndicator.style.display = "none";
      }
      if (senderPskInput) {
        senderPskInput.required = false;
        senderPskInput.style.borderColor = "";
      }
    }
  }
  
  // Update receiver fields visibility and requirements
  if (receiverEncMode) {
    const encMode = parseInt(receiverEncMode.value, 10);
    const isPlaintext = encMode === 0;
    
    // Hide/show key exchange and PSK fields based on decryption mode
    if (receiverKxModeLabel) {
      receiverKxModeLabel.style.display = isPlaintext ? "none" : "block";
    }
    if (receiverPskLabel) {
      receiverPskLabel.style.display = isPlaintext ? "none" : "block";
    }
    
    if (!isPlaintext && receiverKxMode && receiverPskIndicator) {
      const kxMode = receiverKxMode.value;
      const isRequired = kxMode === "psk"; // Required for PSK key exchange with encrypted modes
      
      if (isRequired) {
        receiverPskIndicator.style.display = "inline";
        receiverPskIndicator.textContent = "⚠ REQUIRED for PSK key exchange";
        if (receiverPskInput) {
          receiverPskInput.required = true;
          receiverPskInput.style.borderColor = receiverPskInput.value ? "" : "#ff6b6b";
        }
      } else {
        receiverPskIndicator.style.display = "none";
        if (receiverPskInput) {
          receiverPskInput.required = false;
          receiverPskInput.style.borderColor = "";
        }
      }
    } else {
      if (receiverPskIndicator) {
        receiverPskIndicator.style.display = "none";
      }
      if (receiverPskInput) {
        receiverPskInput.required = false;
        receiverPskInput.style.borderColor = "";
      }
    }
  }
}

// Function to setup attack mode options visibility
function setupAttackModeOptions() {
  const attackModeSelect = document.getElementById("attack-mode");
  if (!attackModeSelect) return;
  
  function updateAttackOptions() {
    const mode = attackModeSelect.value;
    // Hide all options
    document.querySelectorAll(".attack-options").forEach(el => {
      el.style.display = "none";
    });
    // Show relevant options
    const relevantOptions = document.getElementById(`attack-options-${mode}`);
    if (relevantOptions) {
      relevantOptions.style.display = "block";
    }
    
    // Update attack config if role is attacker and attack is active
    if (currentRole === "attacker" && ws && ws.readyState === WebSocket.OPEN) {
      updateAttackConfig();
    }
  }
  
  attackModeSelect.addEventListener("change", updateAttackOptions);
  updateAttackOptions(); // Initial update
  
  // Also listen to changes in attack option inputs
  const dropRateInput = document.getElementById("drop-rate");
  const delayMsInput = document.getElementById("delay-ms");
  const modifyTextInput = document.getElementById("modify-text");
  
  if (dropRateInput) {
    dropRateInput.addEventListener("input", () => {
      if (currentRole === "attacker") updateAttackConfig();
    });
  }
  if (delayMsInput) {
    delayMsInput.addEventListener("input", () => {
      if (currentRole === "attacker") updateAttackConfig();
    });
  }
  if (modifyTextInput) {
    modifyTextInput.addEventListener("input", () => {
      if (currentRole === "attacker") {
        clearTimeout(modifyTextInput.updateTimeout);
        modifyTextInput.updateTimeout = setTimeout(() => {
          updateAttackConfig();
        }, 500);
      }
    });
  }
}

// Function to update attack configuration
function updateAttackConfig() {
  if (currentRole !== "attacker" || !ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }
  
  ensureWs();
  
  const attackMode = document.getElementById("attack-mode").value;
  const dropRate = parseInt(document.getElementById("drop-rate").value, 10) || 0;
  const delayMs = parseInt(document.getElementById("delay-ms").value, 10) || 0;
  const modifyText = document.getElementById("modify-text").value.trim() || "[MITM modified]";
  
  ws.send(JSON.stringify({
    type: "updateAttackConfig",
    config: {
      attackMode,
      dropRate,
      delayMs,
      modifyText
    }
  }));
}

// Function to setup attacker IP input listeners
function setupAttackerIpListeners() {
  const senderIpInput = document.getElementById("attacker-sender-ip");
  const receiverIpInput = document.getElementById("attacker-receiver-ip");
  
  if (senderIpInput) {
    senderIpInput.addEventListener("input", () => {
      updateTargetDisplay();
    });
  }
  
  if (receiverIpInput) {
    receiverIpInput.addEventListener("input", () => {
      updateTargetDisplay();
    });
  }
}

// Function to handle start attack button
function setupStartAttackButton() {
  const startAttackBtn = document.getElementById("start-attack-btn");
  if (!startAttackBtn) return;
  
  startAttackBtn.onclick = () => {
    ensureWs();
    
    if (currentRole !== "attacker") {
      logLine("Only attacker role can start attacks", "error");
      return;
    }
    
    const senderIp = document.getElementById("attacker-sender-ip").value.trim();
    const receiverIp = document.getElementById("attacker-receiver-ip").value.trim();
    const port = parseInt(document.getElementById("target-port").value, 10) || 12347;
    const attackMode = document.getElementById("attack-mode").value;
    const dropRate = parseInt(document.getElementById("drop-rate").value, 10) || 0;
    const delayMs = parseInt(document.getElementById("delay-ms").value, 10) || 0;
    const modifyText = document.getElementById("modify-text").value.trim() || "[MITM modified]";
    
    if (!senderIp && !receiverIp) {
      logLine("Please select at least one target (sender or receiver)", "error");
      addAttackLog("Error: No targets selected", "failed");
      return;
    }
    
    logLine(`Starting attack: mode=${attackMode}`, "role-selected");
    addAttackLog(`Starting attack: ${attackMode}`, "info");
    
    ws.send(JSON.stringify({
      type: "startAttack",
      config: {
        senderIp,
        receiverIp,
        port,
        attackMode,
        dropRate,
        delayMs,
        modifyText
      }
    }));
  };
}

// Setup security listeners after DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    setupSecurityListeners();
    setupAttackModeOptions();
    setupStartAttackButton();
    setupAttackerIpListeners();
  });
} else {
  setupSecurityListeners();
  setupAttackModeOptions();
  setupStartAttackButton();
  setupAttackerIpListeners();
}


