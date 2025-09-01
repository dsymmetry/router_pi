#!/bin/bash
#===============================================================================
# GitHub Repository Setup for EXISTING router_pi Directory
# This script adds Git/GitHub structure to your existing project
#===============================================================================

set -euo pipefail

echo "=== Setting up Git Repository in Existing Directory ==="
echo "Current directory: $(pwd)"
echo

# Confirm we're in the right place
read -p "Are you in your router_pi directory? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Please cd to your router_pi directory first, then run this script"
    exit 1
fi

# Check if git is already initialized
if [[ -d .git ]]; then
    echo "[✓] Git already initialized"
else
    echo "[+] Initializing git repository..."
    git init
fi

# Create directory structure (won't overwrite existing)
echo "[+] Creating directory structure..."
mkdir -p scripts configs docs tests services .github/workflows

#===============================================================================
# Create .gitignore (backs up existing if present)
#===============================================================================
if [[ -f .gitignore ]]; then
    echo "[!] .gitignore exists, backing up to .gitignore.backup"
    cp .gitignore .gitignore.backup
fi

cat > .gitignore << 'EOF'
# Security - NEVER commit these
*.key
*.pem
*.crt
*.password
wifi_password.txt
wpa_passphrase.txt
/secrets/
/private/

# Configuration with sensitive data
configs/private/
*.conf.local
routerpi.conf

# Runtime and state files
/run/
/var/log/
*.pid
*.state
*.leases
/state/

# Backup files
*.backup
*.bak
*.old
*~
*.swp
*.swo
.*.sw?

# OS files
.DS_Store
Thumbs.db
.Trash-*
.nfs*

# IDE
.vscode/
.idea/
*.sublime-*

# Test artifacts
*.pcap
*.cap
test_results/
coverage/

# Build artifacts
*.deb
*.rpm
build/
dist/
EOF

#===============================================================================
# Create README.md (only if it doesn't exist)
#===============================================================================
if [[ ! -f README.md ]]; then
    echo "[+] Creating README.md..."
    cat > README.md << 'EOF'
# 🔐 RPi5 Secure Travel Router

A security-focused travel router implementation for Raspberry Pi 5 with MT7612U (Panda Wireless) support, running on Kali Linux.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%205-red)](https://www.raspberrypi.org/)
[![OS](https://img.shields.io/badge/OS-Kali%20Linux-blue)](https://www.kali.org/)

## 🚀 Features

### Security
- **Advanced Firewall**: Stateful iptables with DDoS protection
- **IDS/IPS**: Real-time intrusion detection with auto-blocking
- **WPA2/WPA3**: Strong encryption with generated passwords
- **DNS Security**: DNSSEC, DNS-over-HTTPS ready
- **Port Scan Detection**: Automatic blocking of suspicious IPs
- **AP Isolation**: Prevent client-to-client communication
- **IPv6 Disabled**: Reduced attack surface

### Networking
- **Dual Band Support**: 2.4GHz and 5GHz (802.11ac)
- **MT7612U Optimized**: Specific optimizations for Panda adapter
- **Auto WAN Detection**: Automatically finds upstream interface
- **DHCP Server**: Built-in with configurable ranges
- **VPN Ready**: WireGuard/OpenVPN client support

## 📋 Quick Start

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/router_pi.git
cd router_pi

# Install dependencies
sudo ./install.sh

# Start router
sudo ./router_pi_secure.sh start

# Check status
sudo ./router_pi_secure.sh status
```

## 📖 Documentation

- [Security Guide](docs/SECURITY.md) - Security features and hardening
- [Network Setup](docs/NETWORKING.md) - Network configuration details
- [VPN Setup](docs/VPN_SETUP.md) - VPN client configuration
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

## 📄 License

MIT License - see [LICENSE](LICENSE) file.
EOF
else
    echo "[✓] README.md already exists, keeping your version"
fi

#===============================================================================
# Create LICENSE (only if it doesn't exist)
#===============================================================================
if [[ ! -f LICENSE ]]; then
    echo "[+] Creating LICENSE..."
    cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2024 Router Pi Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF
else
    echo "[✓] LICENSE already exists"
fi

#===============================================================================
# Create install.sh (only if it doesn't exist)
#===============================================================================
if [[ ! -f install.sh ]]; then
    echo "[+] Creating install.sh..."
    cat > install.sh << 'EOF'
#!/bin/bash
# Installation Script for Router Pi

set -euo pipefail

echo "=== Router Pi Installation ==="

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

echo "[+] Installing required packages..."
apt-get update
apt-get install -y hostapd dnsmasq iptables iptables-persistent \
    iw wireless-tools wpasupplicant net-tools tcpdump \
    vnstat wavemon git openssl firmware-misc-nonfree

echo "[+] Creating directories..."
mkdir -p /etc/routerpi /var/log/routerpi /run/routerpi

echo "[+] Loading MT76 driver..."
modprobe mt76x2u 2>/dev/null || echo "Warning: Could not load mt76x2u module"

echo "=== Installation Complete ==="
EOF
    chmod +x install.sh
else
    echo "[✓] install.sh already exists"
fi

#===============================================================================
# Check for your router scripts
#===============================================================================
echo
echo "[+] Checking for router scripts..."

if [[ -f router_pi.sh ]]; then
    echo "[✓] Found router_pi.sh (original)"
    
    # Create enhanced version if it doesn't exist
    if [[ ! -f router_pi_secure.sh ]]; then
        echo "[!] Creating router_pi_secure.sh (you'll need to add the enhanced code)"
        cp router_pi.sh router_pi_secure.sh
        echo "    Note: Replace router_pi_secure.sh with the enhanced version from our artifact"
    else
        echo "[✓] Found router_pi_secure.sh"
    fi
else
    echo "[!] No router_pi.sh found"
    echo "    Creating placeholder router_pi_secure.sh"
    cat > router_pi_secure.sh << 'EOF'
#!/bin/bash
# PLACEHOLDER: Replace with the enhanced router script
echo "Please replace this with the complete enhanced router script"
exit 1
EOF
    chmod +x router_pi_secure.sh
fi

#===============================================================================
# Create documentation
#===============================================================================
echo "[+] Creating documentation..."

cat > docs/SECURITY.md << 'EOF'
# Security Documentation

## Security Features

1. **Firewall**: Stateful iptables with rate limiting
2. **IDS/IPS**: Real-time monitoring with auto-blocking
3. **WiFi Security**: WPA2/WPA3 with strong passwords
4. **DNS Security**: DNSSEC and rebinding protection
5. **System Hardening**: IPv6 disabled, minimal services

## Running Security Audit

```bash
sudo ./router_pi_secure.sh audit
```
EOF

cat > docs/NETWORKING.md << 'EOF'
# Network Configuration

## Default Settings
- Router IP: 192.168.8.1
- DHCP Range: 192.168.8.10-50
- DNS: 1.1.1.1, 9.9.9.9

## MT7612U Configuration
- 5GHz: Channel 36 (default)
- 2.4GHz: Channel 6
- Mode: Access Point

## Custom Configuration

```bash
# Use 2.4GHz
USE_5GHZ=false sudo ./router_pi_secure.sh start

# Custom IP range
AP_ADDR="10.0.0.1/24" sudo ./router_pi_secure.sh start
```
EOF

cat > docs/TROUBLESHOOTING.md << 'EOF'
# Troubleshooting Guide

## MT7612U Not Detected
```bash
lsusb | grep 0e8d:7612
sudo ./router_pi_secure.sh reset
```

## No WiFi Network
```bash
sudo systemctl status hostapd
sudo journalctl -u hostapd -n 50
```

## No Internet
```bash
ping 1.1.1.1
sudo iptables -t nat -L POSTROUTING -v
```
EOF

cat > docs/VPN_SETUP.md << 'EOF'
# VPN Configuration

## WireGuard Setup
```bash
sudo apt-get install wireguard
wg genkey | tee privatekey | wg pubkey > publickey
```

## OpenVPN Setup
```bash
sudo apt-get install openvpn
sudo openvpn --config /etc/openvpn/client/config.ovpn
```
EOF

#===============================================================================
# Create GitHub Actions workflow
#===============================================================================
echo "[+] Creating GitHub Actions workflow..."
cat > .github/workflows/shellcheck.yml << 'EOF'
name: Shell Script Analysis
on: [push, pull_request]
jobs:
  shellcheck:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: ludeeus/action-shellcheck@master
EOF

#===============================================================================
# Create systemd service
#===============================================================================
cat > services/routerpi.service << 'EOF'
[Unit]
Description=Router Pi Secure Travel Router
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/router_pi/router_pi_secure.sh start
ExecStop=/opt/router_pi/router_pi_secure.sh stop
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

#===============================================================================
# Summary
#===============================================================================
echo
echo "=== Setup Complete ==="
echo
echo "Files in your directory:"
ls -la
echo
echo "Next steps:"
echo "1. Review/update router_pi_secure.sh with the enhanced version"
echo "2. Add all files to git:"
echo "   git add ."
echo "3. Commit your changes:"
echo "   git commit -m \"Initial commit: Secure router with MT7612U support\""
echo "4. Create GitHub repository and push:"
echo "   gh repo create router_pi --public --source=. --push"
echo "   OR"
echo "   git remote add origin https://github.com/YOUR_USERNAME/router_pi.git"
echo "   git push -u origin main"
echo
echo "[✓] Your existing router_pi directory is now ready for GitHub!"