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
  // Detect Termux (Android) - Termux uses python3 but may need explicit path
  let python = "python3";
  if (process.platform === "win32") {
    python = "python";
  } else if (process.env.TERMUX_VERSION || process.env.PREFIX?.includes("com.termux")) {
    // Termux environment detected - use python3 explicitly
    python = "python3";
    console.log("Termux environment detected, using python3");
  }
  
  const initProcess = spawn(python, [pythonScript], {
    cwd: __dirname,
    stdio: "inherit",
    shell: false,
    env: { 
      ...process.env, 
      PYTHONUNBUFFERED: "1",
      // Termux-specific: ensure Python can find modules
      ...(process.env.TERMUX_VERSION ? { PYTHONPATH: process.env.PREFIX + "/lib/python3.11/site-packages" } : {})
    }
  });
  
  initProcess.on("error", (err) => {
    console.log(`NOTE: Could not run Python initialization: ${err.message}`);
    if (err.code === "ENOENT") {
      console.log(`NOTE: Python command '${python}' not found. Please install Python 3.6+`);
      if (process.env.TERMUX_VERSION) {
        console.log("NOTE: For Termux, install Python with: pkg install python");
        console.log("NOTE: Then install cryptography with: pip install cryptography");
      }
    }
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

