# Termux Setup Guide - Quick Reference

## Installing Cryptography Package on Termux

The `cryptography` Python package can be tricky to install on Termux. Here are the solutions, in order of preference:

### ✅ Solution 1: Use Termux Package Manager (BEST)

This is the **recommended method** because it uses pre-built binaries that work reliably:

```bash
# Install Python and cryptography together
pkg install python python-cryptography

# Verify it works
python -c "import cryptography; print('✓ Cryptography installed successfully')"
```

### ✅ Solution 2: Clean Reinstall

If Solution 1 doesn't work, try a clean reinstall:

```bash
# Remove everything
pkg remove python python-pip python-cryptography

# Reinstall fresh
pkg install python python-cryptography

# Test
python -c "import cryptography; print('OK')"
```

### ✅ Solution 3: Install Build Dependencies (for pip)

If you need to use pip instead:

```bash
# Install build dependencies
pkg install python-dev libffi-dev openssl-dev rust

# Upgrade pip tools
pip install --upgrade pip setuptools wheel

# Install cryptography via pip
pip install cryptography
```

### ✅ Solution 4: Fix PyPy/Python Version Mismatch

If you see "pypy and python version don't match":

```bash
# Check what Python you have
python --version
which python

# If it shows PyPy, remove and reinstall standard Python
pkg remove python
pkg install python

# Verify it's standard Python (not PyPy)
python --version
# Should show: Python 3.x.x (not PyPy)
```

## Important Notes

1. **Python crypto utilities are OPTIONAL** - The server works fine without them. The main encryption is handled by Node.js.

2. **If cryptography fails to install**, you can still run the server:
   ```bash
   npm start
   ```
   The server will show a note that Python crypto initialization was skipped, but everything else works.

3. **Always use `pkg install` first** - Termux's package manager has pre-built packages that avoid compilation issues.

## Verification

After installation, test that everything works:

```bash
# Test Python cryptography
python scripts/init_crypto.py

# Should show:
# ✓ Cryptographic utilities initialized successfully
# ✓ Python crypto support is ready
```

If you see errors, the server will still work - Python crypto is just for additional validation/testing features.

