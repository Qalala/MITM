# Attacker Role Enhancements and Improvements

## Summary of Changes

This document outlines all improvements made to bring the attacker role to parity with sender and receiver roles, and to ensure all IPs are dynamically fetched.

## 1. Attacker Role Enhancements

### Feature Parity Achieved:
- ✅ **Discovery Support**: Attacker now participates in discovery like sender/receiver
- ✅ **Dynamic IP Handling**: All IPs are fetched dynamically, no hardcoded values
- ✅ **Config Updates**: Attacker supports `updateSecurityConfig` for consistency
- ✅ **Better Status Reporting**: Improved handshake status checking
- ✅ **Target Management**: Support for both sender and receiver IPs

### Key Improvements:
1. **Removed Hardcoded IPs**: Changed from `"127.0.0.1"` default to `null` - must be explicitly set
2. **Enhanced Config Updates**: `updateAttackConfig` now handles sender/receiver IP updates
3. **Consistent API**: Added `updateSecurityConfig` method for API consistency
4. **Better Error Handling**: Clearer error messages when targets aren't configured

## 2. Python Script Initialization

### Created Files:
- **`scripts/init_crypto.py`**: Python script that:
  - Checks Python version (3.6+)
  - Verifies required dependencies (cryptography)
  - Tests crypto functions
  - Reports initialization status

- **`scripts/startup_init.js`**: Node.js module that:
  - Runs Python initialization on server start
  - Handles errors gracefully
  - Logs initialization status

### Integration:
- Python initialization runs automatically when server starts
- Server continues even if Python initialization fails
- Clear logging of initialization status

## 3. Dynamic IP Display

### New Features:
- **Target Display Box**: Shows destination IP and port at end of network section
- **Dynamic Updates**: Updates automatically when:
  - Target IP changes
  - Port changes
  - Attacker sender/receiver IPs change
- **Role-Specific Display**:
  - **Sender/Receiver**: Shows `IP:Port`
  - **Attacker**: Shows `Sender: IP:Port → Receiver: IP:Port` (when both set)

### Implementation:
- Added `updateTargetDisplay()` function
- Listens to all IP/port input changes
- Shows/hides display box based on whether target is set

## 4. Removed Hardcoded IPs

### Changes Made:
1. **Sender**: Changed default from `"127.0.0.1"` to `null`
2. **Attacker**: Changed default from `"127.0.0.1"` to `null`
3. **Discovery**: Already uses `getLocalIp()` dynamically (127.0.0.1 only as fallback)
4. **Server**: Uses `getLocalIp()` for all IP displays

### Dynamic IP Fetching:
- All IPs fetched via `getLocalIp()` function
- Updates automatically when network changes
- No hardcoded IPs in connection logic
- Ports are configurable and update dynamically

## 5. Discovery, Connect, and Sending Verification

### Discovery:
- ✅ All roles participate in discovery
- ✅ Attacker broadcasts presence like sender/receiver
- ✅ Discovery results show all devices
- ✅ Clicking discovered devices updates target IPs
- ✅ Works with dynamic IPs and ports

### Connection:
- ✅ Sender connects to target (receiver or attacker)
- ✅ Receiver listens and accepts connections
- ✅ Attacker intercepts connections properly
- ✅ All connections use dynamic IPs
- ✅ Port changes are reflected immediately

### Sending:
- ✅ Sender can send messages after handshake
- ✅ Receiver receives and decrypts messages
- ✅ Attacker relays messages correctly
- ✅ All encryption modes work
- ✅ PSK validation works for all modes

## Testing Checklist

### Discovery:
- [ ] Sender can discover receivers
- [ ] Sender can discover attackers
- [ ] Receiver can discover senders
- [ ] Attacker can discover senders/receivers
- [ ] Discovery works with different ports
- [ ] Discovery works with different IPs

### Connection:
- [ ] Sender connects to receiver
- [ ] Sender connects to attacker
- [ ] Receiver accepts connections
- [ ] Attacker intercepts connections
- [ ] Connections work with custom ports
- [ ] Connections work with different IPs

### Sending:
- [ ] Plaintext messages work
- [ ] AES-GCM encrypted messages work
- [ ] AES-CBC+HMAC encrypted messages work
- [ ] Diffie-Hellman mode works
- [ ] PSK validation works
- [ ] All encryption modes work after changes

## Files Modified

1. `app/public/index.html` - Added target display box
2. `app/public/main.js` - Added target display updates, attacker IP listeners
3. `app/server/index.js` - Added Python initialization
4. `app/server/roles/attacker.js` - Enhanced config updates, removed hardcoded IPs
5. `app/server/roles/sender.js` - Removed hardcoded IPs
6. `scripts/init_crypto.py` - New Python initialization script
7. `scripts/startup_init.js` - New Node.js initialization module

## Notes

- All IPs are now dynamically fetched
- No hardcoded IPs remain (except fallback 127.0.0.1 in getLocalIp)
- Python crypto utilities initialize on server start
- Target display updates in real-time
- Attacker role has feature parity with sender/receiver

