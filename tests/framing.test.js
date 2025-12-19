const { test } = require("node:test");
const assert = require("assert");
const { encodeFrame, MAX_FRAME_SIZE, FRAME_TYPES } = require("../core/protocol/framing");

test("encodeFrame produces correct header and payload", () => {
  const payload = Buffer.from("hello", "utf8");
  const buf = encodeFrame(FRAME_TYPES.DATA, payload);
  const length = buf.readUInt32BE(0);
  const type = buf.readUInt8(4);
  const body = buf.slice(5);
  assert.strictEqual(length, 1 + payload.length);
  assert.strictEqual(type, FRAME_TYPES.DATA);
  assert.strictEqual(body.toString("utf8"), "hello");
});

test("encodeFrame rejects too-large payload", () => {
  const big = Buffer.alloc(MAX_FRAME_SIZE);
  assert.throws(() => encodeFrame(FRAME_TYPES.DATA, big));
});


