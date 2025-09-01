# 🔐 RPi5 Secure Travel Router

A security-focused travel router implementation for Raspberry Pi 5 with MT7612U (Panda Wireless) support, running on Kali Linux.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%205-red)](https://www.raspberrypi.org/)
[![OS](https://img.shields.io/badge/OS-Kali%20Linux-blue)](https://www.kali.org/)
[![Security](https://img.shields.io/badge/Security-Hardened-green)](docs/SECURITY.md)

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

### Monitoring
- **Real-time Dashboard**: Traffic and client monitoring
- **Security Auditing**: Built-in security assessment tools
- **Logging**: Comprehensive logs with rotation
- **USB Reset**: Hardware reset capability for adapter

## 📋 Requirements

### Hardware
- Raspberry Pi 5 (4GB+ recommended)
- Panda Wireless USB Adapter (MT7612U chipset)
- Ethernet cable or secondary WiFi for WAN
- Power supply (15W+ recommended)
- Optional: Cooling (for sustained operation)

### Software
- Kali Linux for Raspberry Pi 5
- Root/sudo access
- Git for version control

## 🔧 Quick Start

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/rpi5-secure-router.git
cd rpi5-secure-router

# Make scripts executable
chmod +x *.sh scripts/*.sh

# Install dependencies
sudo ./install.sh

# Start router
sudo ./router_pi_secure.sh start

# Check WiFi password
sudo ./router_pi_secure.sh status
```

## 📖 Usage

### Basic Commands
```bash
./router_pi_secure.sh start    # Start router mode
./router_pi_secure.sh stop     # Stop router mode
./router_pi_secure.sh status   # Show current status
./router_pi_secure.sh monitor  # Real-time monitoring
./router_pi_secure.sh audit    # Security audit
./router_pi_secure.sh reset    # Reset MT7612U adapter
```

### Configuration Options
```bash
# Use 2.4GHz instead of 5GHz
USE_5GHZ=false sudo ./router_pi_secure.sh start

# Custom IP range
AP_ADDR="192.168.50.1/24" sudo ./router_pi_secure.sh start

# Specify interfaces
WAN_IFACE=eth0 LAN_IFACE=wlan1 sudo ./router_pi_secure.sh start
```

## 🔐 Security

See [SECURITY.md](docs/SECURITY.md) for detailed security documentation.

## 📚 Documentation

- [Security Guide](docs/SECURITY.md) - Security features and hardening
- [Network Setup](docs/NETWORKING.md) - Network configuration details
- [VPN Setup](docs/VPN_SETUP.md) - VPN client configuration
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

## ⚠️ Disclaimer

This tool is for authorized security testing and personal use only. Users are responsible for complying with all applicable laws and regulations.

## 🙏 Acknowledgments

- Raspberry Pi Foundation
- Kali Linux Team
- MediaTek for MT7612U chipset
- Open source security community
