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

echo
echo "=== Installation Complete ==="
echo
echo "Next steps:"
echo "1. Connect your Panda WiFi adapter (MT7612U)"
echo "2. Run: sudo ./router_pi_secure.sh start"
echo "3. Check status: sudo ./router_pi_secure.sh status"
echo
echo "For automatic startup:"
echo "    sudo cp services/routerpi.service /etc/systemd/system/"
echo "    sudo systemctl enable routerpi"
echo
