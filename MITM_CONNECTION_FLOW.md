# MITM Connection Flow Explanation

## How Receiver Gets Messages When Sender Connects to Attacker's IP

### The Key: Attacker Creates TWO Connections

The attacker acts as a **proxy** by creating **two separate TCP connections**:

1. **Connection 1**: Sender → Attacker (sender connects to attacker's IP)
2. **Connection 2**: Attacker → Receiver (attacker creates this connection)

Then the attacker **relays frames bidirectionally** between these two connections.

---

## Step-by-Step Flow

### Step 1: Attacker Listens
```
Attacker listens on: 0.0.0.0:12347 (or attacker's IP:12347)
Status: "Waiting for sender to connect..."
```

### Step 2: Sender Connects to Attacker
```
Sender → Connects to → Attacker's IP:12347
Attacker accepts connection → clientConn established
```

**Code:** `app/server/roles/attacker.js:66-97`
- Attacker's server accepts the connection from sender
- This creates `clientConn` (connection from sender to attacker)

### Step 3: Attacker Creates Connection to Receiver
```
Attacker → Creates NEW connection → Receiver's IP:12347
Receiver accepts connection → serverConn established
```

**Code:** `app/server/roles/attacker.js:199-217`
```javascript
serverConn = new net.Socket();
serverConn.connect(targetPort, forwardIp);  // Connects to receiver
```

**Key Point:** The attacker **actively creates** a connection to the receiver using the receiver's IP address (configured in "Target IP" field).

### Step 4: Bidirectional Relay Starts
```
Sender <-> Attacker <-> Receiver
```

**Code:** `app/server/roles/attacker.js:281-295`
```javascript
// Relay from sender to receiver (with attacks applied)
const relayPromise1 = relay(clientConn, serverConn, "sender->receiver");

// Relay from receiver to sender (no attacks, just forward)
const relayPromise2 = relay(serverConn, clientConn, "receiver->sender");
```

---

## Detailed Message Flow

### When Sender Sends a Message:

```
1. Sender writes frame → clientConn (connection to attacker)
   ↓
2. Attacker receives frame from clientConn
   ↓
3. Attacker applies attack mode:
   - MODIFY: Changes frame content
   - DROP: Sets shouldForward = false
   - DELAY: Waits X milliseconds
   - REPLAY: Replaces with previous frame
   - DOWNGRADE: Modifies HELLO frame
   ↓
4. Attacker writes modified frame → serverConn (connection to receiver)
   ↓
5. Receiver receives frame from serverConn
   ↓
6. Receiver processes frame normally
```

### When Receiver Sends a Message (Response):

```
1. Receiver writes frame → serverConn (connection to attacker)
   ↓
2. Attacker receives frame from serverConn
   ↓
3. Attacker forwards frame → clientConn (connection to sender)
   ↓
4. Sender receives frame from clientConn
```

**Note:** Attacks are only applied to frames going **from sender to receiver**, not the reverse.

---

## Visual Diagram

```
┌─────────┐                    ┌──────────┐                    ┌──────────┐
│ Sender  │                    │ Attacker │                    │ Receiver │
└────┬────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │ 1. Connect to                 │                               │
     │    Attacker's IP              │                               │
     ├──────────────────────────────>│                               │
     │                               │                               │
     │                               │ 2. Create connection         │
     │                               │    to Receiver's IP          │
     │                               ├──────────────────────────────>│
     │                               │                               │
     │                               │ 3. Bidirectional relay       │
     │                               │    established                │
     │                               │                               │
     │ 4. Send "Hello"               │                               │
     ├──────────────────────────────>│                               │
     │                               │ 5. Apply attack (modify)     │
     │                               │    "Hello" → "[MITM modified]"│
     │                               │                               │
     │                               │ 6. Forward modified frame     │
     │                               ├──────────────────────────────>│
     │                               │                               │
     │                               │                               │ 7. Receive "[MITM modified]"
     │                               │                               │
     │                               │ 8. Receiver sends response   │
     │                               │<──────────────────────────────┤
     │                               │                               │
     │                               │ 9. Forward response          │
     │<──────────────────────────────┤                               │
     │                               │                               │
```

---

## Code Flow

### Connection Establishment

**File:** `app/server/roles/attacker.js`

1. **Attacker Listens:**
   ```javascript
   server.listen(listenPort, listenIp, 1, () => {
     // Attacker is listening
   });
   ```

2. **Sender Connects:**
   ```javascript
   server = net.createServer((c) => {
     clientConn = c;  // Connection FROM sender
     handleNewClient();
   });
   ```

3. **Attacker Connects to Receiver:**
   ```javascript
   serverConn = new net.Socket();
   serverConn.connect(targetPort, forwardIp);  // Connection TO receiver
   ```

4. **Bidirectional Relay:**
   ```javascript
   // Forward sender → receiver (with attacks)
   relay(clientConn, serverConn, "sender->receiver");
   
   // Forward receiver → sender (no attacks)
   relay(serverConn, clientConn, "receiver->sender");
   ```

### Frame Relay with Attacks

**File:** `app/server/roles/attacker.js:314-503`

```javascript
async function relay(src, dst, direction) {
  const fromSender = direction === "sender->receiver";
  
  for await (const frame of frameIter) {
    let outFrame = frame;
    let shouldForward = true;
    
    // Apply attacks to frames from sender
    if (fromSender && attackActive) {
      if (mode === "modify") {
        // Modify frame
        outFrame = modifiedFrame;
      }
      if (mode === "drop") {
        shouldForward = false;  // Don't forward
      }
      // ... other attack modes
    }
    
    // Forward frame (if not dropped)
    if (shouldForward) {
      const encoded = encodeFrame(outFrame.type, outFrame.payload);
      dst.write(encoded);  // Write to destination
    }
  }
}
```

---

## Key Points

### ✅ Receiver DOES Get Messages

**How:**
1. Attacker creates its own connection to receiver
2. Attacker forwards frames from sender to receiver
3. Receiver receives frames as if they came directly from sender
4. Receiver doesn't know attacker is in the middle

### ✅ Two Separate Connections

- **Connection 1**: Sender ↔ Attacker (sender initiated)
- **Connection 2**: Attacker ↔ Receiver (attacker initiated)

### ✅ Bidirectional Communication

- Sender → Attacker → Receiver (with attacks)
- Receiver → Attacker → Sender (no attacks, just relay)

### ✅ Attacks Applied

- Attacks only applied to sender → receiver direction
- Receiver → sender is just forwarded (no attacks)

---

## Example Scenario

### Setup:
- **Receiver**: Laptop at `192.168.1.100:12347`
- **Attacker**: Android phone at `192.168.1.50:12347`
- **Sender**: Laptop at `192.168.1.200`

### Flow:

1. **Attacker starts:**
   - Listens on `0.0.0.0:12347`
   - Configured with receiver IP: `192.168.1.100`

2. **Sender connects:**
   - Connects to `192.168.1.50:12347` (attacker's IP)
   - Attacker accepts: `clientConn` established

3. **Attacker connects to receiver:**
   - Attacker creates connection to `192.168.1.100:12347` (receiver's IP)
   - Receiver accepts: `serverConn` established

4. **Message flow:**
   - Sender sends "Hello" → `clientConn`
   - Attacker receives from `clientConn`
   - Attacker modifies to "[MITM modified]"
   - Attacker sends to `serverConn`
   - Receiver receives "[MITM modified]" from `serverConn`

5. **Response flow:**
   - Receiver sends "OK" → `serverConn`
   - Attacker receives from `serverConn`
   - Attacker forwards to `clientConn` (no modification)
   - Sender receives "OK" from `clientConn`

---

## Summary

**Question:** How does receiver get messages if sender connects to attacker's IP?

**Answer:** 
1. Attacker creates its own connection to receiver
2. Attacker relays frames between sender and receiver
3. Receiver receives frames through attacker's connection
4. Receiver doesn't know attacker is in the middle

**The attacker acts as a transparent proxy:**
- Sender thinks it's talking to attacker
- Receiver thinks it's talking to sender
- Attacker is in the middle, applying attacks

**This is exactly how MITM attacks work in practice!**

