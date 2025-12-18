## LAN Secure Chat + MITM Demo

This project is a minimal but complete demo of secure Sender–Receiver communication over TCP with a Man‑in‑the‑Middle (MITM) attacker on the same Wi‑Fi network. Any device (laptop or mobile browser) can choose a role (Sender / Receiver / Attacker) at runtime via the web UI.

The stack is:
- **Backend**: Node.js (TCP sockets + crypto) with Express for static files and a WebSocket control channel
- **Frontend**: Simple HTML/JS/CSS running in any modern browser (desktop or mobile)

This satisfies the requirement for a backend that can run on laptops or on Android (via Termux + Node) while the UI runs in the browser.

### Architecture (high level)

```
Browser UI (Sender/Receiver/Attacker)
    │  WebSocket (control, logs, sendMessage)
    ▼
Node app/server/index.js
    ├─ roles/sender   (TCP client, strict setup → streaming)
    ├─ roles/receiver (TCP server, bind 0.0.0.0:12347, listen(1), accept one)
    ├─ roles/attacker (MITM proxy: Sender ↔ Attacker ↔ Receiver)
    └─ lan/discovery  (UDP discovery helper)

core/
    ├─ protocol/
    │   ├─ framing.js     [length‑prefixed frames: 4‑byte len + 1‑byte type + payload]
    │   ├─ constants.js   [ENC_MODES, KX_MODES]
    │   └─ handshake.js   [HELLO / NEGOTIATE / KEY_EXCHANGE helpers]
    ├─ crypto/
    │   ├─ aes_gcm.js     [AES‑256‑GCM]
    │   ├─ aes_cbc_hmac.js[AES‑256‑CBC + HMAC‑SHA256, encrypt‑then‑MAC]
    │   ├─ rsa.js         [RSA‑OAEP for key exchange]
    │   └─ dh.js          [Diffie‑Hellman demo]
    └─ logging/logger.js  [per‑role file + console logging]

scripts/
    ├─ integration_plaintext_vs_gcm.js [quick integration sanity script]
    └─ udp_broadcast_demo.js           [optional 1:M UDP AES‑GCM broadcast demo]

tests/
    ├─ framing.test.js
    └─ crypto.test.js
```

### Protocol summary

- **Transport**: TCP for 1:1 Sender–Receiver and MITM demo (mandatory); optional UDP for 1:M broadcast in `scripts/udp_broadcast_demo.js`.
- **Framing**: Every TCP message is framed as `[4‑byte big‑endian length][1‑byte type][payload]` with **max 1MB** payload.
- **Frame types**: `HELLO`, `NEGOTIATE`, `KEY_EXCHANGE`, `DATA`, `ACK`, `ERROR`, `CLOSE`.
- **Receiver (server)**:
  - Creates `net.createServer`, binds to `0.0.0.0:12347`, **enforces single connection** (listen(1) semantics).
  - On connection: runs strict **setup phase first** (HELLO → NEGOTIATE → KEY_EXCHANGE → ACK), then enters **streaming** loop.
  - Cleanup order: stop processing → close connection → close server socket.
- **Sender (client)**:
  - TCP client connects to `<receiver IP>:12347`.
  - Sends HELLO + performs key exchange before any `DATA`.
  - After receiver `ACK`, enters continuous **send loop** using framed `DATA`.
  - Cleanup order: stop sending → close socket.
- **MITM (proxy)**:
  - Listens on `0.0.0.0:12347`.
  - When Sender connects, Attacker opens its own TCP connection to real Receiver at `<receiver IP>:12347`.
  - Relays frames bidirectionally while optionally applying chosen attack mode (drop/delay/modify/replay/downgrade).

### Encryption modes

The UI lets you select the mode; Receiver and Sender must **match**. Downgrade attacks are prevented by:
- Including the selected mode in the HELLO and NEGOTIATE transcript and requiring an exact match.
- Receiver will send `ERROR` and close if modes differ or are downgraded.

Supported modes:

- **Mode 0 – Plaintext**
  - No encryption, no integrity.
  - `DATA` payload: JSON `{ "text": "..." }`.
  - Demonstrates how easily MITM can read and modify messages.

- **Mode 1 – AES‑256‑GCM (AEAD, recommended)**
  - Symmetric AES‑256‑GCM with integrity.
  - Key establishment:
    - **PSK** (pre‑shared key) from UI, or
    - **RSA‑OAEP**: Receiver generates RSA key pair and sends public key; Sender generates random session key and encrypts it to Receiver.
  - Nonce: 12‑byte random per message (`generateNonce()`), unique per message.
  - Replay protection: each message includes a **sequence number** in AAD; Receiver rejects replays or out‑of‑order (`seq <= lastSeq`).

- **Mode 2 – AES‑CBC + HMAC‑SHA256 (Encrypt‑then‑MAC)**
  - Random 16‑byte IV per message.
  - Session key is split into `encKey` and `macKey`.
  - MAC covers `AAD || IV || ciphertext`; verified in **constant time** via `timingSafeEqual` before decryption.
  - Replay protection via increasing sequence number in AAD.

- **Mode 3 – Diffie‑Hellman (educational)**
  - Uses Node’s `crypto.getDiffieHellman("modp15")` (3072‑bit group).
  - HELLO / KEY_EXCHANGE exchange DH public keys, derive shared secret used as symmetric key.
  - If unauthenticated, a MITM can substitute DH keys and read traffic (classic DH MITM attack).
  - With authenticated parameters (e.g., over RSA or PSK), DH MITM is prevented.

### Attacker interception modes

In Attacker role UI you can select:

- **Passive sniff/log**: relay all frames, log raw bytes (hex/base64) and metadata.
- **Modify plaintext**: if `DATA` appears to be plaintext JSON with `text`, Attacker rewrites the text field.
- **Drop packets**: random drop based on % slider; demonstrates lost messages.
- **Delay**: inserts artificial latency before forwarding frames.
- **Replay**: re‑sends the last `DATA` frame to demonstrate replay behavior. Secure modes reject these when sequence number is stale.
- **Downgrade**: modifies Sender HELLO to attempt forcing plaintext; rejected by Receiver due to mode mismatch.

The attacker never sees keys or decrypted payloads in secure modes (except in DH MITM scenarios you purposely configure to be unauthenticated).

### Discovery (LAN helper)

- Uses UDP broadcast on a separate discovery port.
- Receivers/Attackers broadcast presence including role and port.
- Sender can click **“Auto discover”** to send a probe and see a list of discovered peers.
- If discovery fails (e.g. Wi‑Fi blocks broadcast), you can manually type IP/port.

---

## Running the project

### Prerequisites

- Node.js 18+ (for built‑in `node --test` and modern `crypto` APIs).
- All devices must be on the **same Wi‑Fi / LAN**.
- On Android, you can use **Termux**:
  - Install Node: `pkg install nodejs`
  - Clone/copy this repo into Termux storage.

### Install dependencies

```bash
npm install
```

### Start the app (on any device)

```bash
npm start
```

This starts the HTTP+WebSocket control server (default `PORT=3000`) and serves the UI at:

- `http://<device-local-ip>:3000/`

Open that URL in a browser on:
- Laptop (Windows/macOS/Linux)
- Android mobile (Chrome/Firefox)
- iOS (Safari/Chrome) — UI acts as Sender/Receiver/Attacker; local TCP server is best run on a laptop or Android in most cases.

### Default TCP config (MUST match spec)

- Receiver bind IP: `0.0.0.0`
- Port: `12347`
- Protocol: `TCP`

These are prefilled in the UI. They should “just work” on a typical home/university LAN.

---

## Example role setups

### Laptop 1 (Receiver), Laptop 2 (Sender), Mobile (Attacker)

1. **Laptop 1 – Receiver**
   - Run `npm start`.
   - Visit `http://<laptop1-ip>:3000/` in a browser (or localhost).
   - Choose **Role: Receiver**.
   - Port: `12347`, Encryption: pick mode (e.g. 0 plaintext or 1 AES‑GCM).
   - Click **Set Role**; status shows “Receiver listening”.

2. **Mobile – Attacker**
   - On Android: run `npm start` in Termux, then open `http://<android-ip>:3000/` in the mobile browser.
   - Choose **Role: Attacker**.
   - Target IP: `<laptop1-ip>`, Port: `12347`.
   - Choose an interception mode (e.g. Modify or Passive).
   - Click **Set Role**; status shows attacker listening and forwarding to real receiver.

3. **Laptop 2 – Sender**
   - Run `npm start` or reuse an existing instance.
   - Visit `http://<laptop2-ip>:3000/` in a browser.
   - Choose **Role: Sender**.
   - **Target IP**: `<android-ip>` (Attacker), Port: `12347`.
   - Choose the same encryption mode and key exchange as Receiver.
   - Click **Set Role** and then send messages from the chat input.

### Mobile ↔ Laptop ↔ Laptop permutations

- You can swap roles freely as long as:
  - Sender’s **target IP** points either to Receiver (no MITM) or Attacker (for MITM).
  - Receiver’s listen IP/port stay at `0.0.0.0:12347`.
  - Encryption mode + key exchange configuration match between Sender and Receiver.

---

## Demo walkthroughs

### 1. Plaintext with successful MITM read/modify

1. Receiver: Mode 0 (Plaintext), PSK ignored.
2. Attacker: Role Attacker, Mode **Modify**, set “Modify text” to something obvious (e.g. `HACKED`).
3. Sender: Mode 0 (Plaintext), connects to Attacker IP.
4. Sender sends “hello world”.
5. Observe:
   - Attacker log shows intercepted plaintext and modified frame.
   - Receiver sees altered message (e.g. `HACKED`).

### 2. AES‑GCM with integrity: MITM sees ciphertext, tampering fails

1. Receiver: Mode 1 (AES‑GCM), Key exchange = PSK, PSK = `demo-psk`.
2. Attacker: Mode **Modify** or **Replay**, still positioned as MITM.
3. Sender: Mode 1 (AES‑GCM), Key exchange = PSK, same PSK `demo-psk`, connect to Attacker IP.
4. Sender sends “hello secure”.
5. Observe:
   - Attacker logs show only **ciphertext** (hex/base64) and cannot interpret the message.
   - If Attacker modifies or replays frames, Receiver detects integrity failure or replay and does not accept the tampered content.

### 3. Optional DH demo: unauthenticated vs authenticated

- **Unauthenticated DH**:
  - Use Mode 3 with Key exchange = DH but without any PSK/RSA authentication.
  - A suitably extended Attacker (not fully implemented here beyond downgrade/demo logging) could substitute DH keys and read messages.
- **Authenticated DH**:
  - Wrap DH parameters via RSA or verify via PSK; in that case the same MITM cannot silently change keys.

---

## Testing

### Unit tests

Run:

```bash
npm test
```

This uses `node --test` to run:
- `tests/framing.test.js` – framing encode/size rules.
- `tests/crypto.test.js` – AES‑GCM and AES‑CBC+HMAC round‑trip + tamper detection.

### Integration sanity script

```bash
node scripts/integration_plaintext_vs_gcm.js
```

This spawns a Receiver and Sender in‑process and exercises:
- Plaintext path (mode 0) where messages deliver normally.
- AES‑GCM path (mode 1) using PSK.

### Optional UDP broadcast demo

```bash
# In one terminal (sender)
node scripts/udp_broadcast_demo.js send

# Copy printed key; in another terminal (receiver)
node scripts/udp_broadcast_demo.js recv <printed-key-hex>
```

This uses UDP `SO_BROADCAST` to send AES‑GCM encrypted broadcast messages to `<broadcast>:12347` with a pre‑shared key.

---

## Troubleshooting

- **No connection / timeouts**
  - Ensure firewall allows TCP port **12347** (and **3000** for the UI).
  - Confirm all devices are on the same LAN and can ping each other.
  - Use plain Sender→Receiver (no MITM) first; then insert the Attacker in the middle.

- **Discovery shows no peers**
  - Some networks block UDP broadcast.
  - Manually enter IP/port in the Sender UI.

- **Mobile issues (Android/iOS)**
  - On Android, confirm Termux has network permissions.
  - On iOS, you generally cannot run a long‑lived TCP server app in the background; use a laptop or Android device as Receiver/Attacker and use the iOS device as a UI client (Sender or control UI).

- **MITM appears ineffective in secure modes**
  - That’s expected: AES‑GCM and AES‑CBC+HMAC are designed to prevent undetected tampering.
  - Check Attacker logs; you should see ciphertext and integrity failures / replay rejections.

---

## Security notes

- Uses **Node’s crypto** primitives only (no custom crypto).
- RSA uses **OAEP** padding.
- AES‑GCM nonces are random per message; sequence numbers are included in AAD for replay detection.
- AES‑CBC+HMAC uses encrypt‑then‑MAC, with constant‑time MAC verification before decryption.
- Downgrade attacks are prevented by enforcing matching negotiated modes; HELLO modifications are detected by Receivers.
- Attacker never sees keys or plaintext for secure modes, illustrating confidentiality and integrity under active attack.


