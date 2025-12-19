/**
 * Startup initialization script
 * Runs Python crypto initialization when server starts
 */

const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

function initPythonCrypto() {
  const pythonScript = path.join(__dirname, "init_crypto.py");
  
  // Check if Python script exists
  if (!fs.existsSync(pythonScript)) {
    console.log("NOTE: Python crypto initialization script not found, skipping...");
    return;
  }
  
  // Try to run Python initialization
  const python = process.platform === "win32" ? "python" : "python3";
  const initProcess = spawn(python, [pythonScript], {
    cwd: __dirname,
    stdio: "inherit"
  });
  
  initProcess.on("error", (err) => {
    console.log(`NOTE: Could not run Python initialization: ${err.message}`);
    console.log("NOTE: Server will continue, but Python crypto features may be limited");
  });
  
  initProcess.on("exit", (code) => {
    if (code === 0) {
      console.log("✓ Python crypto utilities initialized");
    } else {
      console.log(`NOTE: Python initialization exited with code ${code}`);
    }
  });
}

module.exports = {
  initPythonCrypto
};

