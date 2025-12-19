#!/usr/bin/env python3
"""
Cryptographic utilities for MITM project.
Supports encryption/decryption operations compatible with the Node.js implementation.
"""

import base64
import json
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Encryption mode constants (matching Node.js)
ENC_MODES = {
    "PLAINTEXT": 0,
    "AES_GCM": 1,
    "AES_CBC_HMAC": 2,
    "DIFFIE_HELLMAN": 3
}

def derive_key_for_aes_gcm(key_material):
    """Derive a 32-byte key for AES-GCM using SHA-256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    if isinstance(key_material, str):
        key_material = key_material.encode('utf-8')
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'mitm-aes-gcm-salt',
        iterations=10000,
        backend=default_backend()
    )
    return kdf.derive(key_material)

def derive_key_for_aes_cbc_hmac(key_material):
    """Derive a 64-byte key (32 enc + 32 mac) for AES-CBC+HMAC using SHA-512."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    if isinstance(key_material, str):
        key_material = key_material.encode('utf-8')
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=b'mitm-aes-cbc-hmac-salt',
        iterations=10000,
        backend=default_backend()
    )
    return kdf.derive(key_material)

def encrypt_gcm(key, nonce, plaintext, aad):
    """Encrypt using AES-256-GCM."""
    if isinstance(key, str):
        key = derive_key_for_aes_gcm(key)
    elif len(key) != 32:
        key = derive_key_for_aes_gcm(key)
    
    if isinstance(nonce, str):
        nonce = base64.b64decode(nonce)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(aad, str):
        aad = aad.encode('utf-8')
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    
    # Split ciphertext and tag (last 16 bytes are tag)
    tag = ciphertext[-16:]
    ciphertext_only = ciphertext[:-16]
    
    return {
        'ciphertext': base64.b64encode(ciphertext_only).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8')
    }

def decrypt_gcm(key, nonce, ciphertext, tag, aad):
    """Decrypt using AES-256-GCM."""
    if isinstance(key, str):
        key = derive_key_for_aes_gcm(key)
    elif len(key) != 32:
        key = derive_key_for_aes_gcm(key)
    
    if isinstance(nonce, str):
        nonce = base64.b64decode(nonce)
    if isinstance(ciphertext, str):
        ciphertext = base64.b64decode(ciphertext)
    if isinstance(tag, str):
        tag = base64.b64decode(tag)
    if isinstance(aad, str):
        aad = aad.encode('utf-8')
    
    aesgcm = AESGCM(key)
    combined = ciphertext + tag
    plaintext = aesgcm.decrypt(nonce, combined, aad)
    
    return plaintext.decode('utf-8')

def encrypt_cbc_hmac(enc_key, mac_key, iv, plaintext, aad):
    """Encrypt using AES-CBC with HMAC-SHA256."""
    if isinstance(enc_key, str):
        enc_key = derive_key_for_aes_cbc_hmac(enc_key)[:32]
    if isinstance(mac_key, str):
        mac_key = derive_key_for_aes_cbc_hmac(mac_key)[32:64]
    if isinstance(iv, str):
        iv = base64.b64decode(iv)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(aad, str):
        aad = aad.encode('utf-8')
    
    # Encrypt
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 padding
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # Compute HMAC
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(aad)
    h.update(iv)
    h.update(ciphertext)
    mac = h.finalize()
    
    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'mac': base64.b64encode(mac).decode('utf-8')
    }

def decrypt_cbc_hmac(enc_key, mac_key, iv, ciphertext, mac, aad):
    """Decrypt using AES-CBC with HMAC-SHA256."""
    if isinstance(enc_key, str):
        enc_key = derive_key_for_aes_cbc_hmac(enc_key)[:32]
    if isinstance(mac_key, str):
        mac_key = derive_key_for_aes_cbc_hmac(mac_key)[32:64]
    if isinstance(iv, str):
        iv = base64.b64decode(iv)
    if isinstance(ciphertext, str):
        ciphertext = base64.b64decode(ciphertext)
    if isinstance(mac, str):
        mac = base64.b64decode(mac)
    if isinstance(aad, str):
        aad = aad.encode('utf-8')
    
    # Verify MAC
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(aad)
    h.update(iv)
    h.update(ciphertext)
    try:
        h.verify(mac)
    except Exception as e:
        raise ValueError(f"MAC verification failed: {e}")
    
    # Decrypt
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]
    
    return plaintext.decode('utf-8')

def generate_nonce():
    """Generate a 12-byte nonce for AES-GCM."""
    return base64.b64encode(os.urandom(12)).decode('utf-8')

def generate_iv():
    """Generate a 16-byte IV for AES-CBC."""
    return base64.b64encode(os.urandom(16)).decode('utf-8')

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python crypto_utils.py <command> [args...]")
        print("Commands:")
        print("  encrypt-gcm <key> <plaintext>")
        print("  decrypt-gcm <key> <nonce> <ciphertext> <tag>")
        print("  encrypt-cbc-hmac <enc_key> <mac_key> <plaintext>")
        print("  decrypt-cbc-hmac <enc_key> <mac_key> <iv> <ciphertext> <mac>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "encrypt-gcm":
        if len(sys.argv) < 4:
            print("Usage: encrypt-gcm <key> <plaintext>")
            sys.exit(1)
        key = sys.argv[2]
        plaintext = sys.argv[3]
        nonce = generate_nonce()
        aad = b"DATA" + b"\x00" * 8  # Simplified AAD
        result = encrypt_gcm(key, nonce, plaintext, aad)
        print(json.dumps({
            'nonce': nonce,
            'ciphertext': result['ciphertext'],
            'tag': result['tag']
        }))
    
    elif command == "decrypt-gcm":
        if len(sys.argv) < 6:
            print("Usage: decrypt-gcm <key> <nonce> <ciphertext> <tag>")
            sys.exit(1)
        key = sys.argv[2]
        nonce = sys.argv[3]
        ciphertext = sys.argv[4]
        tag = sys.argv[5]
        aad = b"DATA" + b"\x00" * 8
        plaintext = decrypt_gcm(key, nonce, ciphertext, tag, aad)
        print(plaintext)
    
    elif command == "encrypt-cbc-hmac":
        if len(sys.argv) < 5:
            print("Usage: encrypt-cbc-hmac <enc_key> <mac_key> <plaintext>")
            sys.exit(1)
        enc_key = sys.argv[2]
        mac_key = sys.argv[3]
        plaintext = sys.argv[4]
        iv = generate_iv()
        aad = b"DATA" + b"\x00" * 8
        result = encrypt_cbc_hmac(enc_key, mac_key, iv, plaintext, aad)
        print(json.dumps({
            'iv': iv,
            'ciphertext': result['ciphertext'],
            'mac': result['mac']
        }))
    
    elif command == "decrypt-cbc-hmac":
        if len(sys.argv) < 7:
            print("Usage: decrypt-cbc-hmac <enc_key> <mac_key> <iv> <ciphertext> <mac>")
            sys.exit(1)
        enc_key = sys.argv[2]
        mac_key = sys.argv[3]
        iv = sys.argv[4]
        ciphertext = sys.argv[5]
        mac = sys.argv[6]
        aad = b"DATA" + b"\x00" * 8
        plaintext = decrypt_cbc_hmac(enc_key, mac_key, iv, ciphertext, mac, aad)
        print(plaintext)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

