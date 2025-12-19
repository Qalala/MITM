## LAN Secure Chat + MITM Demo – Usage Guide

This guide explains:
- **How to run the project on desktop and mobile devices (with exact commands)**
- **How to navigate the UI**
- **Step‑by‑step test cases for the main demo scenarios**

---

## 1. Running the project

### 1.1. Common prerequisites

- **All devices on the same LAN / Wi‑Fi.**
- **Node.js 18+** installed on any device that will run the backend (the Node server).
- A **modern browser** (Chrome/Firefox/Edge/Safari) for the UI.

You only need **one Node server per physical device**; you can then open multiple browser tabs on that device pointing to that server.

---

### 1.2. Desktop / Laptop (Windows, macOS, Linux)

1. **Clone or copy the project** onto the laptop.
2. Open a terminal in the project root (where `package.json` lives).
3. Install dependencies:

```bash
npm install
```

4. Start the server:

```bash
npm start
```

5. In the terminal output, note the device’s **local IP address** (or find it via OS network settings).
6. In a browser on the **same device**, open:

```text
http://localhost:3000/
```

7. From **other devices on the same LAN**, open:

```text
http://<laptop-ip>:3000/
```

Replace `<laptop-ip>` with the actual IP (for example: `192.168.1.23`).

You can repeat steps 2–4 on **other laptops** if you want multiple machines each running their own instance of the demo.

---

### 1.3. Android (Termux + mobile browser)

On Android you can run the **backend** in Termux and the **UI** in the mobile browser.

#### Initial Setup

1. **Install Termux**
   - Download from [F-Droid](https://f-droid.org/packages/com.termux/) or [GitHub releases](https://github.com/termux/termux-app/releases)
   - Avoid Google Play version (often outdated)

2. **Update packages**
   ```bash
   pkg update && pkg upgrade
   ```

3. **Install Node.js**
   ```bash
   pkg install nodejs
   ```

4. **Install Git** (if not already installed)
   ```bash
   pkg install git
   ```

5. **Clone the repository**
   ```bash
   cd ~
   git clone https://github.com/yourusername/lan-secure-chat-mitm-demo.git
   cd lan-secure-chat-mitm-demo
   ```
   > Replace `yourusername` with the actual GitHub username/organization.

6. **Install Python and cryptography (optional, for Python crypto utilities)**
   
   **IMPORTANT for Termux:** Use Termux's package manager instead of pip to avoid version conflicts:
   ```bash
   pkg install python python-cryptography
   ```
   
   This installs pre-built binaries that work correctly on Termux.
   
   **Alternative (if above doesn't work):**
   ```bash
   # Install Python first
   pkg install python
   
   # Install build dependencies
   pkg install python-dev libffi-dev openssl-dev
   
   # Then try pip install
   pip install cryptography
   ```
   
   **If you still get errors:**
   - Make sure you're using the standard Python (not PyPy): `python --version`
   - Reinstall Python: `pkg remove python && pkg install python`
   - Try: `pip install --upgrade pip setuptools wheel` then `pip install cryptography`

7. **Install project dependencies**
   ```bash
   npm install
   ```

#### Running the Server

1. Start the server:
   ```bash
   npm start
   ```

2. Find the Android device's **Wi‑Fi IP address**:
   - In Termux: `ifconfig` or `ip addr show`
   - Or check system Wi‑Fi settings on Android

3. Open in browser:
   - On Android: `http://localhost:3000/`
   - From other devices: `http://<android-ip>:3000/`

#### Updating the Repository

When updates are available:

1. Navigate to project directory:
   ```bash
   cd ~/lan-secure-chat-mitm-demo
   ```

2. Pull latest changes:
   ```bash
   git pull origin main
   ```
   > If you have local changes:
   > ```bash
   > git stash  # Save local changes
   > git pull origin main
   > git stash pop  # Restore local changes
   > ```

3. Update dependencies (if package.json changed):
   ```bash
   npm install
   ```

4. Restart the server:
   ```bash
   npm start
   ```

> **Note:** Android can also be used purely as a UI client by pointing its browser at a server running on a laptop instead.

---

### 1.4. iOS (iPhone / iPad)

On iOS you **do not run the Node server**; instead you use it **as a browser client**.

1. **Start server on laptop or Android** (follow setup instructions above)
2. **Find the server's IP address**:
   - Check terminal output where `npm start` was run
   - Or check network settings on the server device
3. **On iOS device**:
   - Open Safari or Chrome
   - Navigate to: `http://<server-ip>:3000/`
   - Example: `http://192.168.1.20:3000/`
4. **Select role** and use the UI normally

The iOS device acts as a **Sender / Receiver / Attacker** via the browser UI, while the actual TCP sockets run on the server device (laptop or Android).

**Note**: iOS Safari may require explicit permission for WebSocket connections. If you see connection issues, check browser console for errors.

---

## 2. Navigating the UI

Open `http://<server-ip>:3000/` in a browser. **On first launch, only the role selection is visible.** After selecting and setting a role, the role selection disappears and role-specific sections appear.

- **Status bar (`#status`)**
  - Shows connection to the local control server and current role state (e.g. "Receiver listening", "Handshake complete – encrypted").
  - Hidden until a role is set.

- **1. Choose Role** (visible only on startup)
  - `Role` dropdown (`#role-select`): **Sender**, **Receiver**, or **Attacker (MITM)**.
  - `Set Role` button (`#set-role-btn`): applies the selected role with the current configuration.
  - **Important**: After clicking "Set Role", this section disappears and role-specific sections appear.
  - **Note**: Role selection is not restored from previous sessions - you must select a role each time (simulating different devices).

- **2. Network Setup** (appears after setting role)
  - `Local IP` label (`#local-ip`): shows the device's detected IP and default TCP port.
  - `Transport` (`#transport`): normally **TCP**. `UDP broadcast` is for the optional demo script.
  - `Target IP` (`#target-ip`): where the **Sender** or **Attacker** will connect (Receiver or Attacker IP).
  - `Port` (`#target-port`): defaults to **12347** and must match the Receiver/Attacker listening port.
  - `Auto discover` (`#discover-btn`): broadcasts on the LAN and shows results in `#discover-results` (Sender only).
  - `Refresh` (`#refresh-btn`): refreshes discovery (Sender) or checks handshake status (all roles).

- **3. Security** (appears for Sender after setting role)
  - `Encryption mode` (`#enc-mode`):
    - **0 – None (Plaintext)**: Key exchange and PSK fields are **hidden**
    - **1 – AES‑GCM**: Key exchange and PSK fields are **shown**
    - **2 – AES‑CBC + HMAC‑SHA256**: Key exchange and PSK fields are **shown**
    - **3 – Diffie‑Hellman (demo)**: Key exchange and PSK fields are **shown**
  - `Key exchange` (`#kx-mode`): **Only shown for encrypted modes (1-3)**
    - **Pre‑shared key (psk)**: Requires PSK input
    - **RSA**: No PSK needed
    - **Diffie‑Hellman (dh)**: No PSK needed
  - `Pre‑shared key` (`#psk-input`): **Only shown for encrypted modes (1-3)**
    - **Required** when Key exchange = "Pre‑shared key (psk)"
    - Shows indicator "⚠ REQUIRED for PSK key exchange" when required
    - Not needed for RSA or DH key exchange
  - `Demo mode` (`#demo-mode`): enables more verbose logging/steps.

- **3. Decryption Configuration** (appears for Receiver after setting role)
  - `Decryption mode` (`#receiver-decrypt-mode`): Select the decryption method (single mode)
    - **0 – Plaintext (No encryption)**: Key exchange and PSK fields are **hidden**
    - **1 – AES-GCM Decryption**: Key exchange and PSK fields are **shown**
    - **2 – AES-CBC + HMAC-SHA256 Decryption**: Key exchange and PSK fields are **shown**
    - **3 – Diffie-Hellman Decryption**: Key exchange and PSK fields are **shown**
  - The receiver will accept connections from senders using the **exact same encryption mode**.
  - `Key exchange` (`#receiver-kx-mode`): **Only shown for encrypted modes (1-3)**
    - Must match the sender's key exchange method exactly.
  - `Pre‑shared key` (`#receiver-psk-input`): **Only shown for encrypted modes (1-3)**
    - **Required** when Key exchange = "Pre‑shared key (psk)"
    - Must match the sender's PSK exactly
    - Shows indicator "⚠ REQUIRED for PSK key exchange" when required
  - `Demo mode` (`#receiver-demo-mode`): enables more verbose logging/steps.

- **4. Chat / Logs** (appears after setting role)
  - `Chat log` (`#chat-log`): shows sent/received messages and logs.
    - **For encrypted messages**: Shows ciphertext first, then plaintext
      - Example: `→ SENT (ciphertext): <base64>...` followed by `→ SENT (plaintext): Hello`
    - **For plaintext messages**: Shows only plaintext
      - Example: `→ SENT: Hello`
  - `Input` (`#chat-input`) + `Send` button (`#send-btn`): used by **Sender** to send messages (hidden for Receiver and Attacker).

- **Attacker Controls** (appears for Attacker after setting role)
  - `Mode` (`#attack-mode`):
    - **Passive sniff/log**
    - **Modify plaintext**
    - **Drop packets**
    - **Delay packets**
    - **Replay last**
    - **Downgrade attempt**
  - `Drop rate (%)` (`#drop-rate`): how often to drop frames in **Drop** mode.
  - `Delay (ms)` (`#delay-ms`): extra latency in **Delay** mode.
  - `Modify text` (`#modify-text`): replacement text in **Modify plaintext** mode.

---

## 3. Test scenarios and step‑by‑step cases

Below are concrete test scripts you can follow. In all scenarios:

- **Receiver** listens on `0.0.0.0:12347` (default).
- **Sender's Target IP** points either directly to Receiver (no MITM) or to Attacker (for MITM).
- **Sender's Encryption mode** must be one of the **Receiver's supported decryption modes** (selected via checkboxes).
- **Key exchange** must match between Sender and Receiver.

### 3.1. Plaintext chat without MITM (baseline)

**Goal:** Verify basic Sender→Receiver chat works in **Mode 0 (Plaintext)**.

1. **Receiver device**
   - Open `http://<receiver-ip>:3000/` in a browser.
   - Section **1. Choose Role**: select **Receiver**, click **Set Role** (role selection will disappear).
   - Section **2. Network Setup**:
     - Ensure **Transport = TCP**.
     - Leave **Port = 12347**.
   - Section **3. Decryption Capabilities**:
     - Check **Plaintext (No encryption) – Mode 0** (and any other modes you want to support).
     - **Key exchange = Pre‑shared key** (PSK is ignored in plaintext).
   - Confirm status shows **"Receiver listening on 0.0.0.0:12347"**.

2. **Sender device**
   - Open `http://<sender-ip>:3000/` in a browser.
   - Role: **Sender**, click **Set Role** (role selection will disappear).
   - Network:
     - **Target IP = <receiver-ip>**
     - **Port = 12347**
     - **Transport = TCP**
   - Security:
     - **Encryption mode = 0 – None (Plaintext)**.
     - **Key exchange = Pre‑shared key**.
   - Click **Connect** button (appears for Sender).
   - When status indicates handshake complete or ready, go to **4. Chat / Logs**.
   - Type `Hello plaintext` and click **Send**.

3. **Expected results**
   - Receiver’s `#chat-log` shows: `RECV (plaintext): Hello plaintext`.
   - Sender log shows message was sent.

---

### 3.2. Plaintext with successful MITM read/modify

**Goal:** Demonstrate that plaintext traffic can be read and modified by an active MITM.

1. **Receiver (Laptop 1)**
   - As in 3.1, configure **Receiver**, **TCP**, **Port 12347**.
   - **Decryption Capabilities**: Check **Plaintext (No encryption) – Mode 0**.
   - **Key exchange = Pre‑shared key**.

2. **Attacker (Mobile or Laptop 2)**
   - Open `http://<attacker-ip>:3000/`.
   - Role: **Attacker (MITM)**, click **Set Role**.
   - Network:
     - **Target IP = <receiver-ip>**
     - **Port = 12347**.
   - Attacker Controls:
     - **Mode = Modify plaintext**.
     - **Modify text = HACKED** (for example).

3. **Sender (Laptop 3 or another device)**
   - Open `http://<sender-ip>:3000/`.
   - Role: **Sender**, click **Set Role**.
   - Network:
     - **Target IP = <attacker-ip>** (not the receiver directly).
     - **Port = 12347**.
   - Security:
     - **Encryption mode = 0 – None (Plaintext)**.
     - **Key exchange = Pre‑shared key**.
   - After handshake, send the message `hello world`.

4. **Expected results**
   - **Attacker log** (`#chat-log` on attacker device) shows intercepted frame contents in hex/base64 and logs indicating a **modified plaintext DATA frame**.
   - **Receiver log** shows the altered message, e.g. `RECV (plaintext): HACKED`.
   - **Sender log** still shows it sent `hello world`.

---

### 3.3. AES‑GCM with integrity – MITM sees ciphertext, tampering fails

**Goal:** Show that with **AES‑GCM**, the attacker cannot read or modify traffic without detection.

1. **Receiver**
   - Role: **Receiver**, Port = `12347`, Transport = TCP.
   - Decryption Capabilities:
     - Check **AES-GCM Decryption – Mode 1** (and any other modes you want to support).
     - **Key exchange = Pre‑shared key**.
     - Set **PSK = demo-psk** (or another shared string, but use the same for Sender).

2. **Attacker**
   - Role: **Attacker (MITM)**.
   - Network:
     - **Target IP = <receiver-ip>**, **Port = 12347**.
   - Attacker Controls:
     - **Mode = Modify plaintext** or **Replay last** (both should fail against integrity).

3. **Sender**
   - Role: **Sender**.
   - Network:
     - **Target IP = <attacker-ip>**, **Port = 12347**.
   - Security:
     - **Encryption mode = 1 – AES‑GCM**.
     - **Key exchange = Pre‑shared key**.
     - **PSK = demo-psk** (exactly the same as Receiver).
   - After handshake, send the message `hello secure`.

4. **Expected results**
   - **Attacker log** shows frames as ciphertext (hex/base64) and cannot interpret the plaintext.
   - If the attacker is in **Modify** or **Replay** mode, Receiver detects integrity/replay issues and **does not accept modified content** (or logs replay detection).
   - **Receiver log** shows the original text received correctly when packets are not tampered with.

---

### 3.4. AES‑CBC + HMAC‑SHA256 – encrypt‑then‑MAC with replay protection

**Goal:** Demonstrate authenticated encryption using **AES‑CBC + HMAC‑SHA256** with replay protection.

1. **Receiver**
   - Role: **Receiver**, Port = `12347`, Transport = TCP.
   - Decryption Capabilities:
     - Check **AES-CBC + HMAC-SHA256 Decryption – Mode 2** (and any other modes you want to support).
     - **Key exchange = Pre‑shared key** (or RSA/DH if you prefer).
     - Set **PSK** to some value, e.g. `cbc-psk`.

2. **Sender**
   - Role: **Sender**.
   - Network:
     - **Target IP = <receiver-ip>** (no MITM for this basic scenario).
   - Security:
     - **Encryption mode = 2 – AES‑CBC + HMAC‑SHA256**.
     - **Key exchange = Pre‑shared key**.
     - **PSK = cbc-psk** (same as Receiver).
   - After handshake, send `cbc secret one` and then `cbc secret two`.

3. **Optional: Attacker replay test**
   - Insert an **Attacker** between Sender and Receiver as in previous scenarios.
   - Set **Mode = Replay last**.

4. **Expected results**
   - Receiver log shows decrypted messages as:
     - `RECV (AES-CBC+HMAC): cbc secret one`
     - `RECV (AES-CBC+HMAC): cbc secret two`
   - When attacker replays old frames, Receiver logs **replay detected** and ignores them (due to sequence number checks).

---

### 3.5. Diffie‑Hellman (unauthenticated vs authenticated concept)

**Goal:** Illustrate how unauthenticated DH can be vulnerable to MITM, while authenticated DH can be secure (conceptual demo).

1. **Unauthenticated DH setup**
   - Receiver:
     - Role: **Receiver**, Port `12347`, Transport TCP.
     - Decryption Capabilities:
       - Check **Diffie-Hellman Decryption – Mode 3** (and any other modes you want to support).
       - **Key exchange = dh** (if used).
   - Sender:
     - Role: **Sender**, Target IP = `<receiver-ip>`, **Encryption mode = 3 – Diffie‑Hellman (demo)**, same kx as Receiver.
   - Optionally insert an **Attacker** in passive mode to log frames and reason about substituting DH keys.

2. **Authenticated DH (concept)**
   - Extend the configuration by combining DH with PSK/RSA (not fully automated in this UI).
   - Use PSK or RSA to authenticate parameters or wrap DH keys.

3. **Expected results**
   - With unauthenticated DH, you can reason how an attacker *could* substitute keys.
   - With an authenticated setup, such substitution would be detected, preventing silent MITM on key exchange.

---

### 3.6. Optional: UDP broadcast demo (scripts)

**Goal:** Test the optional 1:M UDP broadcast with AES‑GCM.

1. **On one terminal (Sender side)**

```bash
node scripts/udp_broadcast_demo.js send
```

2. Copy the printed key from the sender output.

3. **On another terminal (Receiver side)**

```bash
node scripts/udp_broadcast_demo.js recv <printed-key-hex>
```

4. **Expected results**
   - Receivers show AES‑GCM decrypted broadcast messages; tampering should fail due to integrity checks.

---

## 4. Troubleshooting

### 4.1. Cryptography Package Issues on Termux

If you encounter errors like "pypy and python version don't match" or "cryptography installation failed" on Termux:

**Solution 1: Use Termux Package Manager (Recommended)**
```bash
# Remove any pip-installed cryptography
pip uninstall cryptography

# Install from Termux repositories (pre-built, works reliably)
pkg install python-cryptography
```

**Solution 2: Reinstall Python and Dependencies**
```bash
# Remove Python completely
pkg remove python python-pip

# Reinstall fresh
pkg install python python-cryptography

# Verify installation
python -c "import cryptography; print('OK')"
```

**Solution 3: Install Build Dependencies (if pip install is needed)**
```bash
# Install required build tools
pkg install python-dev libffi-dev openssl-dev rust

# Upgrade pip and build tools
pip install --upgrade pip setuptools wheel

# Install cryptography
pip install cryptography
```

**Solution 4: Check Python Version**
```bash
# Make sure you're using standard Python (not PyPy)
python --version
# Should show: Python 3.x.x

# If you see PyPy, reinstall:
pkg remove python
pkg install python
```

**Note:** The Python crypto utilities are **optional**. The server will run without them, but some crypto validation features may be limited. The main encryption/decryption is handled by Node.js, so the server works fine even if Python cryptography isn't installed.

---

This `USAGE.md` file is intended as a practical companion to `README.md`, focusing on concrete steps and test cases you can run on real desktop and mobile devices.


