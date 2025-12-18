// Encryption modes
const ENC_MODES = {
  PLAINTEXT: 0,
  AES_GCM: 1,
  AES_CBC_HMAC: 2,
  DIFFIE_HELLMAN: 3
};

// Key exchange modes
const KX_MODES = {
  PSK: "psk",
  RSA: "rsa",
  DH: "dh"
};

module.exports = {
  ENC_MODES,
  KX_MODES
};


