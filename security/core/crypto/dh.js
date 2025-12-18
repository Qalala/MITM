const crypto = require("crypto");

function createDh() {
  // Use a safe pre-defined group
  const dh = crypto.getDiffieHellman("modp15"); // 3072-bit
  dh.generateKeys();
  return dh;
}

function computeSecret(ownDh, otherPublicKey) {
  return ownDh.computeSecret(otherPublicKey);
}

module.exports = {
  createDh,
  computeSecret
};


