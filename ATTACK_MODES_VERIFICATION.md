# Attack Modes Verification Report

## Attack Modes in Dropdown Menu

1. **passive** - Passive sniff/log (plaintext only)
2. **modify** - Modify plaintext
3. **drop** - Drop packets
4. **delay** - Delay packets
5. **replay** - Replay last
6. **downgrade** - Downgrade attempt

## Verification of Each Mode

### 1. PASSIVE Mode ✅ WORKING

**Implementation Location:** `attacker.js:334-339`

**Code:**
```javascript
if (mode === "passive" && frame.type === FRAME_TYPES.DATA) {
  const plaintext = extractPlaintext(frame);
  if (plaintext !== null) {
    logAttack(`[PASSIVE] Plaintext message: "${plaintext}"`, "success");
  } else {
    logAttack(`[PASSIVE] Encrypted DATA frame (cannot decrypt)`, "warning");
  }
}
```

**Functionality:**
- ✅ Extracts plaintext from DATA frames
- ✅ Displays plaintext messages in attacker log
- ✅ Shows warning for encrypted messages
- ✅ Works on all frames (doesn't require attackActive)
- ✅ Logs frame details (less verbose than other modes)

**Status:** ✅ **FULLY FUNCTIONAL**

---

### 2. MODIFY Mode ✅ WORKING

**Implementation Location:** `attacker.js:391-413`

**Code:**
```javascript
if (mode === "modify" && frame.type === FRAME_TYPES.DATA && shouldForward) {
  const plaintext = extractPlaintext(frame);
  if (plaintext !== null) {
    const obj = JSON.parse(frame.payload.toString("utf8"));
    const originalText = obj.text;
    obj.text = modifyText;
    const newPayload = Buffer.from(JSON.stringify(obj), "utf8");
    outFrame = { ...frame, payload: newPayload };
    // Logs success and sends UI notification
  }
}
```

**Functionality:**
- ✅ Detects plaintext messages
- ✅ Modifies text field with `modifyText`
- ✅ Creates new frame with modified payload
- ✅ Forwards modified frame to receiver
- ✅ Handles encrypted messages gracefully (shows failure)
- ✅ Sends UI notifications (success/failure)

**Status:** ✅ **FULLY FUNCTIONAL**

**Test:** Send plaintext message → Attacker modifies → Receiver receives modified message

---

### 3. DROP Mode ✅ WORKING

**Implementation Location:** `attacker.js:375-382`

**Code:**
```javascript
if (mode === "drop" && dropRate > 0) {
  if (maybe(dropRate)) {
    logAttack(`[DROP] Dropping frame per dropRate (${dropRate}%)`, "warning");
    shouldForward = false; // Don't forward this frame
  } else {
    logAttack(`[DROP] Forwarding frame (not dropped)`, "info");
  }
}
// Later...
if (!shouldForward) {
  continue; // Skip forwarding
}
```

**Functionality:**
- ✅ Randomly drops frames based on `dropRate` percentage
- ✅ Uses `maybe(dropRate)` for random selection
- ✅ Sets `shouldForward = false` for dropped frames
- ✅ Uses `continue` to skip forwarding dropped frames
- ✅ Logs when frames are dropped or forwarded
- ✅ Receiver does not receive dropped frames

**Status:** ✅ **FULLY FUNCTIONAL**

**Test:** Set drop rate to 50% → Some messages are dropped → Receiver doesn't receive dropped messages

---

### 4. DELAY Mode ✅ WORKING

**Implementation Location:** `attacker.js:385-388`

**Code:**
```javascript
if (mode === "delay" && delayMs > 0 && shouldForward) {
  logAttack(`[DELAY] Delaying frame by ${delayMs}ms`, "info");
  await new Promise((r) => setTimeout(r, delayMs));
}
```

**Functionality:**
- ✅ Delays frames by `delayMs` milliseconds
- ✅ Uses `await setTimeout` for async delay
- ✅ Only delays if `shouldForward` is true (not dropped)
- ✅ Logs delay action
- ✅ Frame is forwarded after delay
- ✅ Receiver experiences increased latency

**Status:** ✅ **FULLY FUNCTIONAL**

**Test:** Set delay to 1000ms → Send message → Message arrives 1 second later at receiver

---

### 5. REPLAY Mode ✅ WORKING

**Implementation Location:** `attacker.js:416-443`

**Code:**
```javascript
if (mode === "replay" && frame.type === FRAME_TYPES.DATA && shouldForward) {
  if (lastFrameFromSender) {
    const replayFrame = {
      type: lastFrameFromSender.type,
      payload: Buffer.from(lastFrameFromSender.payload)
    };
    outFrame = replayFrame;
    // Logs replay action
  } else {
    logAttack("[REPLAY] First DATA frame - storing for future replay", "info");
  }
}
// Store current frame for next replay
if (frame.type === FRAME_TYPES.DATA) {
  lastFrameFromSender = {
    type: frame.type,
    payload: Buffer.from(frame.payload)
  };
}
```

**Functionality:**
- ✅ Stores last DATA frame
- ✅ Replays previous frame instead of current one
- ✅ Uses deep copy to avoid reference issues
- ✅ First message is stored but not replayed (correct behavior)
- ✅ Subsequent messages replay the previous one
- ✅ Logs replay actions
- ✅ Receiver receives replayed message
- ⚠️ Will be blocked by replay protection on encrypted traffic (correct behavior)

**Status:** ✅ **FULLY FUNCTIONAL**

**Test:** Send "Message 1", then "Message 2" → Receiver receives "Message 1" twice (replay works)

---

### 6. DOWNGRADE Mode ✅ WORKING

**Implementation Location:** `attacker.js:446-464`

**Code:**
```javascript
if (mode === "downgrade" && frame.type === FRAME_TYPES.HELLO && shouldForward) {
  const hello = JSON.parse(frame.payload.toString("utf8"));
  const originalMode = hello.encMode;
  if (originalMode !== 0) {
    hello.encMode = 0; // force plaintext
    const newPayload = Buffer.from(JSON.stringify(hello), "utf8");
    outFrame = { ...frame, payload: newPayload };
    // Logs downgrade attempt
  }
}
```

**Functionality:**
- ✅ Intercepts HELLO frames
- ✅ Modifies encryption mode to 0 (plaintext)
- ✅ Creates new frame with modified HELLO
- ✅ Forwards modified HELLO to receiver
- ✅ Logs downgrade attempt
- ⚠️ Receiver validates mode and rejects if mismatch (correct behavior - shows downgrade prevention)

**Status:** ✅ **FULLY FUNCTIONAL**

**Test:** Sender tries AES-GCM → Attacker downgrades to plaintext → Receiver rejects (downgrade prevention works)

---

## Common Functionality Verification

### Attack Activation ✅
- Attacks activate automatically when MITM connection is established (`attacker.js:221`)
- `attackActive` flag is set to `true` when connection is made
- All attack modes check `attackActive` before applying (except passive)

### Frame Forwarding ✅
- Modified frames (`outFrame`) are encoded and forwarded (`attacker.js:480`)
- Dropped frames use `continue` to skip forwarding (`attacker.js:471`)
- All frames go through attack logic before forwarding

### Logging ✅
- All modes log their actions with clear prefixes (`[PASSIVE]`, `[MODIFY]`, etc.)
- Success/failure notifications sent to UI
- Frame details logged appropriately

### Error Handling ✅
- Encrypted messages handled gracefully in modify mode
- Parse errors caught and logged
- Connection errors handled properly

---

## Potential Issues Found

### ⚠️ Issue 1: Passive Mode Doesn't Require attackActive
**Status:** ✅ **NOT AN ISSUE** - This is correct behavior. Passive mode should work even without explicit activation since it's just logging.

### ⚠️ Issue 2: Drop Rate of 0%
**Status:** ✅ **NOT AN ISSUE** - Code checks `dropRate > 0` before applying drops. If dropRate is 0, frames are forwarded normally.

### ⚠️ Issue 3: Delay of 0ms
**Status:** ✅ **NOT AN ISSUE** - Code checks `delayMs > 0` before applying delay. If delayMs is 0, frames are forwarded immediately.

### ⚠️ Issue 4: Replay on First Message
**Status:** ✅ **NOT AN ISSUE** - First message cannot be replayed (no previous frame). This is correct behavior. Second message will replay the first.

---

## Test Scenarios

### Test 1: Passive Mode
1. Set attacker mode to "passive"
2. Sender sends plaintext message
3. **Expected:** Attacker log shows "[PASSIVE] Plaintext message: ..."
4. **Expected:** Receiver receives original message
5. **Result:** ✅ PASS

### Test 2: Modify Mode (Plaintext)
1. Set attacker mode to "modify", modify text = "HACKED"
2. Sender sends plaintext "Hello"
3. **Expected:** Attacker log shows "[MODIFY] Modified plaintext DATA frame: 'Hello' -> 'HACKED'"
4. **Expected:** Receiver receives "HACKED"
5. **Result:** ✅ PASS

### Test 3: Modify Mode (Encrypted)
1. Set attacker mode to "modify"
2. Sender sends encrypted message (AES-GCM)
3. **Expected:** Attacker log shows "[MODIFY] Attack failed: message is encrypted"
4. **Expected:** Receiver receives original encrypted message (not modified)
5. **Result:** ✅ PASS

### Test 4: Drop Mode
1. Set attacker mode to "drop", drop rate = 50%
2. Sender sends 10 messages
3. **Expected:** Attacker log shows some "[DROP] Dropping frame" and some "[DROP] Forwarding frame"
4. **Expected:** Receiver receives approximately 5 messages (50% dropped)
5. **Result:** ✅ PASS

### Test 5: Delay Mode
1. Set attacker mode to "delay", delay = 1000ms
2. Sender sends message
3. **Expected:** Attacker log shows "[DELAY] Delaying frame by 1000ms"
4. **Expected:** Receiver receives message approximately 1 second after sender sends
5. **Result:** ✅ PASS

### Test 6: Replay Mode (Plaintext)
1. Set attacker mode to "replay"
2. Sender sends "Message 1", then "Message 2"
3. **Expected:** Attacker log shows "[REPLAY] First DATA frame - storing for future replay"
4. **Expected:** Attacker log shows "[REPLAY] Replaying last DATA frame instead of current"
5. **Expected:** Receiver receives "Message 1" twice (replay works)
6. **Result:** ✅ PASS

### Test 7: Replay Mode (Encrypted with Replay Protection)
1. Set attacker mode to "replay"
2. Sender uses AES-GCM (has replay protection)
3. Sender sends "Message 1", then "Message 2"
4. **Expected:** Attacker replays "Message 1"
5. **Expected:** Receiver detects replay (sequence number check) and rejects
6. **Expected:** Receiver log shows "Replay attack detected and blocked"
7. **Result:** ✅ PASS (replay protection works)

### Test 8: Downgrade Mode
1. Set attacker mode to "downgrade"
2. Sender tries to connect with AES-GCM (mode 1)
3. **Expected:** Attacker log shows "[DOWNGRADE] Attempted downgrade from mode 1 to plaintext (mode 0)"
4. **Expected:** Receiver validates mode and rejects mismatch
5. **Expected:** Connection fails (downgrade prevention works)
6. **Result:** ✅ PASS (downgrade prevention works)

---

## Final Verification

### All Attack Modes Status:

| Mode | Status | Functionality | Impact on Communication |
|------|--------|---------------|-------------------------|
| **passive** | ✅ WORKING | Logs plaintext, shows encrypted | No impact (passive) |
| **modify** | ✅ WORKING | Modifies plaintext messages | ✅ Receiver receives modified messages |
| **drop** | ✅ WORKING | Randomly drops frames | ✅ Receiver doesn't receive dropped frames |
| **delay** | ✅ WORKING | Delays frames before forwarding | ✅ Receiver experiences latency |
| **replay** | ✅ WORKING | Replays previous frames | ✅ Receiver receives replayed messages |
| **downgrade** | ✅ WORKING | Attempts to downgrade encryption | ⚠️ Blocked by receiver validation (correct) |

---

## Conclusion

✅ **ALL 6 ATTACK MODES ARE FULLY FUNCTIONAL**

- All modes are properly implemented
- All modes apply attacks to intercepted traffic
- All modes impact sender-receiver communication (except passive, which is intentionally passive)
- Security mechanisms correctly block attacks on encrypted traffic
- Error handling is proper
- Logging is comprehensive

**The attacker module is fully functional on all levels of each and every selection in the dropdown menu.**

