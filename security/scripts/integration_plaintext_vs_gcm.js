// Very small integration sanity script (CI-friendly) to exercise plaintext and AES-GCM paths.
// For full demos, use the UI across devices.
const { createReceiver } = require("../app/server/roles/receiver");
const { createSender } = require("../app/server/roles/sender");

async function runOnce(encMode) {
  console.log("Running integration with encMode =", encMode);
  const fakeWs = { send: () => {} };
  const receiver = createReceiver({ port: 12347, encMode, kxMode: "psk", psk: "demo-psk" }, fakeWs);
  await new Promise((r) => setTimeout(r, 300));
  const sender = createSender(
    { targetIp: "127.0.0.1", port: 12347, encMode, kxMode: "psk", psk: "demo-psk" },
    fakeWs
  );
  await new Promise((r) => setTimeout(r, 800));
  await sender.sendMessage("hello from integration " + encMode);
  await new Promise((r) => setTimeout(r, 800));
  await sender.stop();
  await receiver.stop();
}

if (require.main === module) {
  (async () => {
    await runOnce(0); // plaintext
    await runOnce(1); // AES-GCM
    process.exit(0);
  })();
}


