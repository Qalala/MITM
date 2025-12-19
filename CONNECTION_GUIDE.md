# Connection and Discovery Guide

## Overview

This guide explains how devices connect to each other and how the discovery mechanism works in the LAN Secure Chat + MITM Demo.

## Connection Methods

### Manual Connection (Required for All Roles)

**All roles require manual connection to the network:**

1. **Sender**: Must click the "Connect" button after setting role and entering target IP
2. **Receiver**: Automatically starts listening when role is set (no connect button needed)
3. **Attacker**: Automatically starts listening when role is set (no connect button needed)

### Connection Flow

#### Sender Connection Process:
1. User selects "Sender" role and clicks "Set Role"
2. User enters Target IP (Receiver or Attacker IP address)
3. User configures encryption settings
4. User clicks "Connect" button
5. Sender establishes TCP connection to target IP:port
6. Handshake process begins (HELLO → NEGOTIATE → KEY_EXCHANGE → ACK)
7. Once handshake completes, sender can send messages

#### Receiver Connection Process:
1. User selects "Receiver" role and clicks "Set Role"
2. User configures decryption mode (must match sender's encryption mode)
3. Receiver automatically starts listening on 0.0.0.0:12347
4. Receiver waits for incoming connections
5. When sender connects, receiver accepts connection
6. Handshake process begins
7. Once handshake completes, receiver can receive messages

#### Attacker Connection Process:
1. User selects "Attacker" role and clicks "Set Role"
2. User enters Target IP (real Receiver's IP address)
3. Attacker automatically starts listening on 0.0.0.0:12347
4. When sender connects to attacker, attacker:
   - Accepts connection from sender
   - Establishes new connection to real receiver
   - Begins bidirectional relay between sender and receiver

## Discovery Mechanism

### How Discovery Works

The discovery system uses **UDP broadcast** on port **41234** to help devices find each other on the local network.

#### Components:
- **Discovery Port**: 41234 (UDP)
- **Main Communication Port**: 12347 (TCP)
- **Broadcast Address**: 255.255.255.255

### Discovery Protocol

1. **Presence Broadcasting**:
   - Each device (Receiver/Attacker) broadcasts its presence every 3 seconds
   - Broadcast includes: role, IP address, and main port (12347)
   - Uses UDP broadcast to 255.255.255.255:41234

2. **Probe Request**:
   - Sender can click "Auto discover" button to send a probe
   - Probe is broadcast to all devices on the network
   - Devices listening respond directly to the sender with their presence

3. **Response Handling**:
   - When a device receives a probe, it responds directly to the sender's IP
   - Response includes: role, IP address, and port
   - Sender collects all responses and displays them in discovery results

### Discovery Flow Diagram

```
Sender                    Network                    Receiver/Attacker
  |                          |                              |
  |--[Probe Broadcast]------>|                              |
  |                          |--[Probe]------------------->|
  |                          |                              |
  |                          |<--[Direct Response]----------|
  |<--[Response]-------------|                              |
  |                          |                              |
  |  (Displays discovered    |                              |
  |   devices in UI)          |                              |
```

### Using Discovery

1. **For Sender**:
   - Click "Auto discover" button
   - Wait 1-2 seconds for responses
   - Discovery results will show all available Receivers and Attackers
   - Click on a discovered device to auto-fill the Target IP field

2. **For Receiver/Attacker**:
   - No action needed - they automatically broadcast their presence
   - They automatically respond to probe requests

### Discovery Troubleshooting

#### If Discovery Doesn't Work:

1. **Check Network Configuration**:
   - Ensure all devices are on the same LAN/WiFi network
   - Some networks block UDP broadcast (corporate networks, some public WiFi)
   - Try manual IP entry if broadcast is blocked

2. **Firewall Issues**:
   - Ensure UDP port 41234 is not blocked
   - Ensure TCP port 12347 is not blocked
   - Check both inbound and outbound rules

3. **Network Restrictions**:
   - Some routers block broadcast traffic
   - VPNs may interfere with discovery
   - Mobile hotspots may have restrictions

4. **Manual Connection**:
   - If discovery fails, you can always manually enter the IP address
   - Find the device's IP address from:
     - Network settings on the device
     - "Local IP" display in the UI
     - Router's connected devices list

### Manual Connection Steps

If discovery doesn't work, follow these steps:

1. **Find Receiver/Attacker IP**:
   - Look at the "Local IP" display in the Receiver/Attacker UI
   - Or check network settings on that device
   - Example: 192.168.1.20

2. **Configure Sender**:
   - Enter the IP address in "Target IP" field
   - Enter port (default: 12347)
   - Click "Connect"

3. **Verify Connection**:
   - Status should show "Handshake complete - encrypted"
   - If connection fails, check:
     - IP address is correct
     - Port matches (12347)
     - Encryption mode matches between sender and receiver
     - Key exchange mode matches
     - PSK matches (if using PSK)

## Network Requirements

### Ports Used:
- **TCP 12347**: Main communication port (Sender ↔ Receiver/Attacker)
- **UDP 41234**: Discovery port (broadcast and probe responses)

### Network Conditions:
- All devices must be on the same LAN/WiFi network
- Devices must be able to reach each other (ping should work)
- Firewall must allow TCP 12347 and UDP 41234

## Connection States

### Sender States:
1. **Not Connected**: No connection established
2. **Connecting**: TCP connection in progress
3. **Handshake in Progress**: HELLO/NEGOTIATE/KEY_EXCHANGE happening
4. **Handshake Complete**: Ready to send messages

### Receiver States:
1. **Listening**: Waiting for connections on 0.0.0.0:12347
2. **Connection Received**: Sender connected, handshake starting
3. **Handshake in Progress**: Processing handshake
4. **Handshake Complete**: Ready to receive messages

### Attacker States:
1. **Listening**: Waiting for sender connections on 0.0.0.0:12347
2. **Sender Connected**: Sender connected, connecting to receiver
3. **Relay Active**: Both connections established, relaying traffic

## Common Connection Issues

### "Connection refused" or "Cannot connect"
- **Cause**: Receiver/Attacker not listening or wrong IP/port
- **Solution**: 
  - Verify Receiver/Attacker has clicked "Set Role"
  - Check IP address is correct
  - Verify port is 12347
  - Check firewall settings

### "Handshake not complete"
- **Cause**: Encryption mode or key exchange mismatch
- **Solution**:
  - Ensure sender's encryption mode matches receiver's decryption mode
  - Ensure key exchange modes match
  - If using PSK, ensure both have the same key

### "Mode mismatch" error
- **Cause**: Sender and receiver using different encryption/decryption modes
- **Solution**:
  - Sender: Check encryption mode dropdown
  - Receiver: Check decryption mode dropdown
  - They must match exactly (e.g., both Mode 1 for AES-GCM)

### Discovery shows no devices
- **Cause**: UDP broadcast blocked or devices not on same network
- **Solution**:
  - Use manual IP entry
  - Check network configuration
  - Verify all devices on same LAN
  - Check firewall for UDP 41234

## Best Practices

1. **Always verify IP addresses** before connecting
2. **Use discovery first**, fall back to manual entry if needed
3. **Check encryption/decryption modes match** before connecting
4. **Verify PSK matches** if using pre-shared key
5. **Test with plaintext first** (Mode 0) to verify basic connectivity
6. **Check firewall settings** if connections fail

## Summary

- **All roles require manual setup** (sender clicks Connect, receiver/attacker auto-listen)
- **Discovery uses UDP broadcast** on port 41234 to find devices
- **Main communication uses TCP** on port 12347
- **If discovery fails**, use manual IP entry
- **Encryption modes must match** between sender and receiver
- **Key exchange modes must match** between sender and receiver

