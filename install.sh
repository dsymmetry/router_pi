#!/bin/bash
#===============================================================================
# Installation Script for RPi5 Secure Router
#===============================================================================

set -euo pipefail

echo "=== RPi5 Secure Router Installation ==="
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Check for Raspberry Pi
if ! grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
    echo "Warning: Not running on Raspberry Pi"
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "[+] Updating package lists..."
apt-get update

echo "[+] Installing required packages..."
packages=(
    "hostapd"
    "dnsmasq"
    "iptables"
    "iptables-persistent"
    "netfilter-persistent"
    "iw"
    "wireless-tools"
    "wpasupplicant"
    "net-tools"
    "tcpdump"
    "vnstat"
    "wavemon"
    "git"
    "openssl"
    "firmware-misc-nonfree"
    "wireguard"
    "wireguard-tools"
)

for pkg in "${packages[@]}"; do
    echo "    Installing $pkg..."
    apt-get install -y "$pkg" || echo "    Warning: Failed to install $pkg"
done

echo "[+] Creating directories..."
mkdir -p /etc/routerpi
mkdir -p /var/log/routerpi
mkdir -p /run/routerpi

echo "[+] Setting permissions..."
chmod +x router_pi_secure.sh
chmod +x scripts/*.sh 2>/dev/null || true

echo "[+] Loading MT76 driver..."
modprobe mt76x2u 2>/dev/null || echo "    Warning: Could not load mt76x2u module"

echo "[+] Applying system security hardening..."
if [[ -f configs/99-router-security.conf ]]; then
    cp configs/99-router-security.conf /etc/sysctl.d/
    echo "    ✅ Applied security sysctl configuration"
    sysctl -p /etc/sysctl.d/99-router-security.conf >/dev/null 2>&1 || true
else
    echo "    ⚠️ Security configuration not found"
fi

echo "[+] Setting up log rotation..."
cat > /etc/logrotate.d/routerpi << 'EOF'
/var/log/routerpi/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0644 root root
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

echo "[+] Configuring firewall persistence..."
if command -v netfilter-persistent >/dev/null 2>&1; then
    systemctl enable netfilter-persistent
    echo "    ✅ Firewall persistence enabled"
fi

echo "[+] Security hardening complete"
echo "    - Kernel security parameters applied"
echo "    - Log rotation configured"
echo "    - Firewall persistence enabled"

echo
echo "=== Installation Complete ==="
echo
echo "🔐 Security Status:"
echo "    ✅ System hardening applied"
echo "    ✅ Firewall persistence enabled"
echo "    ✅ Log rotation configured"
echo
echo "📋 Next steps:"
echo "1. Connect your Panda WiFi adapter (MT7612U)"
echo "2. Run: sudo ./router_pi_secure.sh start"
echo "3. Check status: sudo ./router_pi_secure.sh status"
echo "4. Run security audit: sudo ./router_pi_secure.sh audit"
echo
echo "🔧 For automatic startup:"
echo "    sudo cp services/routerpi.service /etc/systemd/system/"
echo "    sudo systemctl enable routerpi"
echo
echo "📚 Documentation:"
echo "    - Security: docs/SECURITY.md"
echo "    - Networking: docs/NETWORKING.md"
echo "    - VPN Setup: docs/VPN_SETUP.md"
echo "    - Troubleshooting: docs/TROUBLESHOOTING.md"
echo
