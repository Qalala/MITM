const fs = require("fs");
const path = require("path");

function getLogPath(role) {
  const logsDir = path.join(process.cwd(), "logs");
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }
  const file = `${role || "app"}.log`;
  return path.join(logsDir, file);
}

function log(role, message) {
  const ts = new Date().toISOString();
  const line = `[${ts}] [${role}] ${message}\n`;
  process.stdout.write(line);
  const filePath = getLogPath(role);
  fs.appendFile(filePath, line, () => {});
}

module.exports = {
  log
};


