#!/usr/bin/env python3
"""
Initialization script for cryptographic utilities.
This script is run when the server starts to ensure all crypto dependencies are available.
"""

import sys
import subprocess
import importlib.util

def check_python_version():
    """Check if Python version is 3.6+."""
    if sys.version_info < (3, 6):
        print("ERROR: Python 3.6 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    return True

def check_dependencies():
    """Check if required dependencies are installed."""
    required_packages = {
        'cryptography': 'cryptography',
        'json': None,  # Built-in
        'base64': None,  # Built-in
        'os': None  # Built-in
    }
    
    missing = []
    for module_name, package_name in required_packages.items():
        if package_name is None:
            # Built-in module, just check if it can be imported
            try:
                __import__(module_name)
            except ImportError:
                missing.append(module_name)
        else:
            # External package
            spec = importlib.util.find_spec(module_name)
            if spec is None:
                missing.append(package_name)
    
    if missing:
        print("WARNING: Missing dependencies:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("\nTo install missing packages, run:")
        print(f"  pip install {' '.join(missing)}")
        return False
    
    return True

def test_crypto_functions():
    """Test that crypto functions work correctly."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.backends import default_backend
        import os
        
        # Test AES-GCM
        key = os.urandom(32)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        plaintext = b"test message"
        aad = b"test aad"
        
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
        
        if decrypted != plaintext:
            print("ERROR: Crypto test failed - decryption mismatch")
            return False
        
        print("✓ Cryptographic functions working correctly")
        return True
    except Exception as e:
        print(f"ERROR: Crypto test failed: {e}")
        return False

def main():
    """Main initialization function."""
    print("Initializing cryptographic utilities...")
    
    if not check_python_version():
        sys.exit(1)
    
    if not check_dependencies():
        print("\nNOTE: Some dependencies are missing. Crypto utilities may not work.")
        print("The server will continue, but encryption features may be limited.")
        return
    
    if not test_crypto_functions():
        print("\nWARNING: Crypto test failed. Encryption features may not work correctly.")
        return
    
    print("✓ Cryptographic utilities initialized successfully")
    print("✓ Python crypto support is ready")

if __name__ == "__main__":
    main()

