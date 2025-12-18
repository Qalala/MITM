const MAX_FRAME_SIZE = 1024 * 1024; // 1MB

// Frame types
const FRAME_TYPES = {
  HELLO: 1,
  NEGOTIATE: 2,
  KEY_EXCHANGE: 3,
  DATA: 4,
  ACK: 5,
  ERROR: 6,
  CLOSE: 7
};

function encodeFrame(type, payloadBuffer) {
  if (!Buffer.isBuffer(payloadBuffer)) {
    payloadBuffer = Buffer.from(payloadBuffer || "");
  }
  const length = 1 + payloadBuffer.length;
  if (length > MAX_FRAME_SIZE) {
    throw new Error("Frame too large");
  }
  const buffer = Buffer.alloc(4 + length);
  buffer.writeUInt32BE(length, 0);
  buffer.writeUInt8(type, 4);
  payloadBuffer.copy(buffer, 5);
  return buffer;
}

/**
 * Async generator that yields { type, payload } frames from a Node.js socket/stream.
 * @param {import('net').Socket} socket
 */
async function* decodeFrames(socket) {
  let buffer = Buffer.alloc(0);

  for await (const chunk of socket) {
    buffer = Buffer.concat([buffer, chunk]);

    while (buffer.length >= 5) {
      const length = buffer.readUInt32BE(0);
      if (length > MAX_FRAME_SIZE) {
        throw new Error("Received frame too large");
      }
      if (buffer.length < 4 + length) {
        break; // wait for more data
      }
      const type = buffer.readUInt8(4);
      const payload = buffer.slice(5, 4 + length);
      buffer = buffer.slice(4 + length);
      yield { type, payload };
    }
  }
}

module.exports = {
  MAX_FRAME_SIZE,
  FRAME_TYPES,
  encodeFrame,
  decodeFrames
};


