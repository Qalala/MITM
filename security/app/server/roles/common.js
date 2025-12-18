const net = require("net");
const { encodeFrame, decodeFrames, FRAME_TYPES } = require("../../../core/protocol/framing");
const { log } = require("../../../core/logging/logger");

function sendUi(ws, payload) {
  try {
    ws.send(JSON.stringify(payload));
  } catch {
    // ignore
  }
}

function logUi(ws, role, message) {
  log(role, message);
  sendUi(ws, { type: "log", message: `[${role}] ${message}` });
}

function createTcpServer(bindIp, port, onConnection) {
  return new Promise((resolve, reject) => {
    const server = net.createServer(async (conn) => {
      onConnection(conn);
    });
    server.on("error", reject);
    server.listen(port, bindIp, () => {
      resolve(server);
    });
  });
}

function createTcpClient(targetIp, port) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    socket.once("error", reject);
    socket.connect(port, targetIp, () => {
      socket.removeAllListeners("error");
      resolve(socket);
    });
  });
}

module.exports = {
  sendUi,
  logUi,
  createTcpServer,
  createTcpClient,
  encodeFrame,
  decodeFrames,
  FRAME_TYPES
};


