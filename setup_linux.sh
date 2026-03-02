#!/bin/bash
echo "==================================================="
echo "[ Kharma Sentinel - Linux/macOS Setup ]"
echo "==================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./setup_linux.sh) to install globally."
  exit
fi

# Determine python command
PYTHON_CMD="python3"
if ! command -v $PYTHON_CMD &> /dev/null; then
    PYTHON_CMD="python"
    if ! command -v $PYTHON_CMD &> /dev/null; then
        echo "[ERROR] Python 3 is not installed or not in PATH."
        exit 1
    fi
fi

# Install dependencies globally
echo "[1/3] Installing dependencies..."
$PYTHON_CMD -m pip install -r requirements.txt

# Make main.py executable
echo "[2/3] Configuring permissions..."
chmod +x kharma/main.py

# Add shebang if missing
if ! head -n 1 kharma/main.py | grep -q "^#!/"; then
    sed -i '1s/^/#!\/usr\/bin\/env python3\n/' kharma/main.py
fi

# Create symlink
echo "[3/3] Creating global symlink at /usr/local/bin/kharma..."
ln -sf "$(pwd)/kharma/main.py" /usr/local/bin/kharma

echo ""
echo "==================================================="
echo "Setup Complete!"
echo "You can now run 'sudo kharma' from anywhere."
echo "==================================================="
