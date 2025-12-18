// Optional 1:M UDP broadcast demo using pre-shared AES key.
const dgram = require("dgram");
const { encryptGcm, generateKey, generateNonce } = require("../core/crypto/aes_gcm");

const PORT = 12347;
const BROADCAST_ADDR = "255.255.255.255";

function runSender(pskHex) {
  const key = pskHex ? Buffer.from(pskHex, "hex") : generateKey();
  console.log("Using AES-GCM key (hex):", key.toString("hex"));
  const sock = dgram.createSocket("udp4");
  sock.bind(() => {
    sock.setBroadcast(true);
    console.log("UDP broadcast sender ready on port", PORT);
    let seq = 0;
    setInterval(() => {
      const msg = `Broadcast message #${++seq}`;
      const nonce = generateNonce();
      const aad = Buffer.from("BCAST");
      const { ciphertext, tag } = encryptGcm(key, nonce, Buffer.from(msg, "utf8"), aad);
      const payload = Buffer.from(
        JSON.stringify({
          nonce: nonce.toString("base64"),
          ciphertext: ciphertext.toString("base64"),
          tag: tag.toString("base64")
        }),
        "utf8"
      );
      sock.send(payload, 0, payload.length, PORT, BROADCAST_ADDR);
      console.log("Sent:", msg);
    }, 2000);
  });
}

function runReceiver(pskHex) {
  const key = Buffer.from(pskHex, "hex");
  const sock = dgram.createSocket("udp4");
  sock.on("message", (msg) => {
    try {
      const obj = JSON.parse(msg.toString("utf8"));
      const nonce = Buffer.from(obj.nonce, "base64");
      const ct = Buffer.from(obj.ciphertext, "base64");
      const tag = Buffer.from(obj.tag, "base64");
      const aad = Buffer.from("BCAST");
      const { decryptGcm } = require("../core/crypto/aes_gcm");
      const pt = decryptGcm(key, nonce, ct, tag, aad);
      console.log("Received:", pt.toString("utf8"));
    } catch (e) {
      console.error("Failed to decrypt/parse broadcast:", e.message);
    }
  });
  sock.bind(PORT, "0.0.0.0", () => {
    console.log("UDP broadcast receiver bound on 0.0.0.0:" + PORT);
  });
}

if (require.main === module) {
  const mode = process.argv[2];
  const keyHex = process.argv[3];
  if (mode === "send") {
    runSender(keyHex);
  } else if (mode === "recv" && keyHex) {
    runReceiver(keyHex);
  } else {
    console.log("Usage: node scripts/udp_broadcast_demo.js send [keyHex]");
    console.log("   or: node scripts/udp_broadcast_demo.js recv <keyHex>");
  }
}


