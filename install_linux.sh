#!/bin/bash
# KnightGuard GRC — PII Scanner Agent Linux Installer
# Runs as Python script — no GLIBC dependency issues

set -e
INSTALL_DIR="/opt/knightguard-agent"
SERVICE_NAME="knightguard-pii-agent"

echo "╔══════════════════════════════════════════╗"
echo "║  KnightGuard GRC PII Scanner Agent       ║"
echo "║  Linux Installer (Python-based)           ║"
echo "╚══════════════════════════════════════════╝"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Installing Python3..."
    apt-get update -qq && apt-get install -y python3 python3-pip
fi

echo "Python: $(python3 --version)"

# Create install dir
mkdir -p "$INSTALL_DIR"

# Download agent files
BASE_URL="https://raw.githubusercontent.com/accredionqualis/pii-scanner-agent/main"
for f in agent_main.py detectors.py file_scanner.py api_client.py agent_requirements.txt; do
    curl -sL "$BASE_URL/$f" -o "$INSTALL_DIR/$f"
done

# Install dependencies
pip3 install -r "$INSTALL_DIR/agent_requirements.txt" --break-system-packages 2>/dev/null || \
pip3 install -r "$INSTALL_DIR/agent_requirements.txt"

# Create wrapper script
cat > /usr/local/bin/knightguard-agent << 'EOF'
#!/bin/bash
exec python3 /opt/knightguard-agent/agent_main.py "$@"
EOF
chmod +x /usr/local/bin/knightguard-agent

echo ""
echo "✓ Agent installed!"
echo ""
echo "Configure with:"
echo "  knightguard-agent configure --server https://api.knightguardgrc.com --api-key YOUR_KEY"
echo ""
echo "Then start:"
echo "  knightguard-agent start"
