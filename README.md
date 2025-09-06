# 🔐 RPi5 Secure Travel Router

A comprehensive, security-hardened travel router implementation for Raspberry Pi 5 with MT7612U (Panda Wireless) support, running on Kali Linux. Designed for cybersecurity professionals and privacy-conscious travelers who need enterprise-grade security in hostile network environments.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%205-red)](https://www.raspberrypi.org/)
[![OS](https://img.shields.io/badge/OS-Kali%20Linux-blue)](https://www.kali.org/)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-green)](docs/SECURITY.md)
[![Version](https://img.shields.io/badge/Version-2.0.0-blue)](router_pi_secure.sh)

## 🛡️ Security Features Summary

| Feature | Implementation | Status |
|---------|---------------|---------|
| **Firewall** | Stateful iptables with rate limiting and DDoS protection | ✅ |
| **DNS Security** | DNSSEC, rebinding protection, malware blocking | ✅ |
| **WiFi Security** | WPA2/WPA3, AP isolation, 25-char generated passwords | ✅ |
| **IDS/IPS** | Suricata integration with auto-blocking | ✅ |
| **System Hardening** | IPv6 disabled, kernel security, service minimization | ✅ |
| **VPN Support** | WireGuard/OpenVPN with kill switch | ✅ |
| **Monitoring** | Real-time traffic, security events, adapter health | ✅ |
| **Logging** | Comprehensive security audit trail | ✅ |

## 🏗️ Project Structure

```
router_pi/
├── router_pi.sh              # Original basic router script
├── router_pi_secure.sh       # 🔐 Enhanced secure router (MAIN)
├── install.sh                # Dependency installation
├── scripts/                  # 🛠️ Utility scripts
│   ├── mt7612u_monitor.sh    # MT7612U adapter health monitoring
│   ├── vpn_setup.sh          # VPN client configuration (WG/OpenVPN)
│   ├── security_audit.sh     # Comprehensive security assessment
│   ├── network_diag.sh       # Network diagnostics and monitoring
│   └── test_connectivity.sh  # Quick connectivity verification
├── configs/                  # 📁 Configuration templates
│   ├── hostapd_mt7612u.conf  # Optimized hostapd for MT7612U
│   ├── dnsmasq_secure.conf   # Secure DNS/DHCP configuration
│   └── iptables_rules.sh     # Advanced firewall rules
├── services/                 # 🔧 System integration
│   └── routerpi.service      # Systemd service file
└── docs/                     # 📚 Documentation
    ├── SECURITY.md           # Comprehensive security guide
    ├── NETWORKING.md         # Network configuration details
    ├── TROUBLESHOOTING.md    # Problem resolution guide
    └── VPN_SETUP.md          # VPN configuration instructions
```

## 🚀 Advanced Features

### 🔥 Multi-Layer Firewall
- **Default DROP Policy**: Deny-all approach with explicit allow rules
- **DDoS Protection**: SYN flood, connection flood, and rate limiting
- **Port Scan Detection**: Automatic detection and blocking of reconnaissance
- **Invalid Packet Filtering**: Protection against malformed packets
- **Connection Limiting**: Per-IP connection limits to prevent abuse
- **Custom Security Chains**: Modular firewall architecture

### 📡 MT7612U Optimization
- **Dual Band Support**: 2.4GHz (802.11n) and 5GHz (802.11ac)
- **Hardware-Specific Tuning**: Optimized HT/VHT capabilities
- **Automatic Recovery**: Health monitoring with automatic reset
- **Power Management**: Optimized for stability and performance
- **Driver Management**: Automatic module loading and configuration

### 🔍 DNS Security
- **Secure Upstream**: Cloudflare (1.1.1.1), Quad9 (9.9.9.9), Google (8.8.8.8)
- **Malware Blocking**: Built-in blocklist for known threats
- **DNS Rebinding Protection**: Prevents DNS-based attacks
- **Privacy Protection**: No query forwarding without domain
- **Cache Optimization**: Enhanced performance with security

### 🚨 Intrusion Detection
- **Suricata Integration**: Real-time network traffic analysis
- **Automatic Blocking**: Malicious IPs blocked for configurable time
- **Threat Signatures**: Updated signature-based detection
- **Behavioral Analysis**: Anomaly detection for unknown threats
- **Alert System**: Comprehensive logging and notification

### 📊 Monitoring & Diagnostics
- **Real-time Monitoring**: Live traffic and connection tracking
- **Health Checks**: Continuous adapter and system monitoring
- **Performance Metrics**: CPU, memory, temperature, and network stats
- **Security Auditing**: Automated security posture assessment
- **Log Management**: Structured logging with rotation

## 📋 Requirements

### Hardware Requirements
- **Raspberry Pi 5** (4GB+ RAM recommended for optimal performance)
- **Panda Wireless PAU09** or compatible MT7612U-based adapter
- **Ethernet connection** or secondary WiFi for WAN uplink
- **Quality power supply** (Official Pi 5 PSU or 15W+ USB-C)
- **MicroSD card** (32GB+ Class 10 or better)
- **Optional**: Cooling solution for sustained operation

### Software Requirements
- **Kali Linux** for Raspberry Pi 5 (latest version)
- **Root/sudo access** for system configuration
- **Git** for version control and updates
- **Internet connection** for initial setup and updates

### Network Requirements
- **WAN Interface**: Ethernet or secondary WiFi for internet access
- **LAN Interface**: MT7612U adapter for client access point
- **IP Range**: Default 192.168.8.0/24 (configurable)

## 🔧 Installation & Setup

### Quick Start
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/router_pi.git
cd router_pi

# Install dependencies and configure system
sudo ./install.sh

# Start the secure router
sudo ./router_pi_secure.sh start

# Check status and get WiFi credentials
sudo ./router_pi_secure.sh status
```

### Advanced Installation
```bash
# Custom configuration during startup
USE_5GHZ=true \
AP_ADDR="10.0.0.1/24" \
SECURITY_MODE=high \
ENABLE_IDS=true \
sudo ./router_pi_secure.sh start
```

### Systemd Service (Auto-start)
```bash
# Install as system service
sudo cp services/routerpi.service /etc/systemd/system/
sudo systemctl enable routerpi
sudo systemctl start routerpi
```

## 📖 Usage Guide

### Core Commands
```bash
# Router management
sudo ./router_pi_secure.sh start     # Start secure router mode
sudo ./router_pi_secure.sh stop      # Stop and restore normal operation
sudo ./router_pi_secure.sh status    # Show detailed status
sudo ./router_pi_secure.sh monitor   # Real-time monitoring dashboard
sudo ./router_pi_secure.sh audit     # Security audit and recommendations
sudo ./router_pi_secure.sh reset     # Reset MT7612U adapter
```

### Diagnostic Tools
```bash
# Network diagnostics
sudo ./scripts/network_diag.sh full         # Complete network analysis
sudo ./scripts/network_diag.sh connectivity # Internet connectivity test
sudo ./scripts/network_diag.sh monitor      # Real-time traffic monitoring
sudo ./scripts/network_diag.sh speed        # Network speed test

# Adapter monitoring
sudo ./scripts/mt7612u_monitor.sh check     # Adapter health check
sudo ./scripts/mt7612u_monitor.sh stats     # Detailed adapter statistics
sudo ./scripts/mt7612u_monitor.sh monitor   # Continuous health monitoring

# Security auditing
sudo ./scripts/security_audit.sh full       # Comprehensive security audit
sudo ./scripts/security_audit.sh quick      # Quick security check
sudo ./scripts/security_audit.sh firewall   # Firewall-specific audit
```

### VPN Integration
```bash
# VPN setup and management
sudo ./scripts/vpn_setup.sh check           # Check VPN support
sudo ./scripts/vpn_setup.sh setup-wg myvpn  # Setup WireGuard config
sudo ./scripts/vpn_setup.sh connect wg myvpn # Connect to VPN
sudo ./scripts/vpn_setup.sh status          # Check VPN status
sudo ./scripts/vpn_setup.sh kill-switch     # Setup kill switch
```

## ⚙️ Configuration

### Environment Variables
```bash
# Network Configuration
WAN_IFACE=eth0                    # WAN interface (auto-detected)
LAN_IFACE=wlan0                   # AP interface (MT7612U)
AP_ADDR=192.168.8.1/24           # Router IP and subnet
USE_5GHZ=true                     # Use 5GHz band (false for 2.4GHz)

# Security Configuration
SECURITY_MODE=high                # Security level (high/medium/low)
ENABLE_IDS=true                   # Enable Suricata IDS
ENABLE_IPS=true                   # Enable auto-blocking
MAX_CONN_PER_IP=20               # Connection limit per IP
BLOCK_TIME=3600                   # Auto-unblock time (seconds)

# WiFi Configuration
SSID_PREFIX=SecureTravel         # WiFi network prefix
COUNTRY_CODE=US                   # Regulatory domain
HIDDEN_SSID=false                 # Hide SSID broadcast
```

### Security Profiles
```bash
# High Security (Default)
SECURITY_MODE=high sudo ./router_pi_secure.sh start

# Medium Security (Balanced)
SECURITY_MODE=medium sudo ./router_pi_secure.sh start

# Low Security (Performance focused)
SECURITY_MODE=low sudo ./router_pi_secure.sh start
```

## 🔐 Security Architecture

### Defense in Depth
1. **Perimeter Defense**: Advanced firewall with DDoS protection
2. **Network Security**: DNS filtering and traffic analysis
3. **Wireless Security**: WPA2/WPA3 with client isolation
4. **System Hardening**: Kernel tuning and service minimization
5. **Monitoring**: Real-time threat detection and response

### Threat Model
- **Hostile Networks**: Protection against malicious infrastructure
- **Man-in-the-Middle**: DNS security and VPN integration
- **Reconnaissance**: Port scan detection and blocking
- **DoS Attacks**: Rate limiting and connection management
- **Data Exfiltration**: Traffic monitoring and analysis

## 📊 Monitoring & Logging

### Log Files
```
/var/log/routerpi/
├── router.log          # General router operations
├── security.log        # Security events and threats
├── traffic.log         # Network traffic statistics
└── mt7612u_monitor.log # Adapter health monitoring
```

### Real-time Monitoring
```bash
# Security events
tail -f /var/log/routerpi/security.log

# Traffic analysis
sudo ./router_pi_secure.sh monitor

# System resources
watch -n 1 'cat /proc/loadavg; free -h'
```

## 🚨 Security Alerts

### Automatic Response
- **Port Scans**: Immediate IP blocking with logging
- **DDoS Attempts**: Rate limiting and connection drops
- **Malware DNS**: Automatic domain blocking
- **SSH Brute Force**: Progressive blocking with backoff

### Manual Response
```bash
# View blocked IPs
cat /run/routerpi/blocked_ips

# Security audit
sudo ./router_pi_secure.sh audit

# Emergency reset
sudo ./router_pi_secure.sh stop && sudo ./router_pi_secure.sh start
```

## 🛠️ Troubleshooting

### Quick Diagnostics
```bash
# Full system diagnostic
sudo ./scripts/network_diag.sh full

# Adapter-specific issues
sudo ./scripts/mt7612u_monitor.sh check

# Security audit
sudo ./scripts/security_audit.sh quick
```

### Common Issues
- **MT7612U Not Detected**: Check USB connection, power supply, driver loading
- **No WiFi Network**: Verify hostapd configuration and interface status
- **No Internet**: Check NAT rules, IP forwarding, and upstream connectivity
- **Poor Performance**: Monitor system resources and adapter health

See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for comprehensive problem resolution.

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [SECURITY.md](docs/SECURITY.md) | Complete security implementation guide |
| [NETWORKING.md](docs/NETWORKING.md) | Network configuration and optimization |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Problem diagnosis and resolution |
| [VPN_SETUP.md](docs/VPN_SETUP.md) | VPN client configuration guide |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development and contribution guidelines |

## 🔄 Updates & Maintenance

### Git-based Updates
```bash
# Pull latest updates
git pull origin main

# Review changes
git log --oneline -10

# Apply updates (review first!)
sudo ./install.sh
```

### Security Maintenance
```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Rotate WiFi password
sudo rm /run/routerpi/wifi_password
sudo ./router_pi_secure.sh stop && sudo ./router_pi_secure.sh start

# Security audit
sudo ./router_pi_secure.sh audit
```

## 🤝 Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Coding standards
- Testing procedures
- Pull request process

### Development Workflow
1. Fork the repository
2. Create feature branch
3. Implement changes
4. Test thoroughly
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## ⚠️ Legal Disclaimer

This software is designed for:
- **Authorized security testing**
- **Personal privacy protection**
- **Educational purposes**
- **Legitimate network administration**

Users are solely responsible for compliance with all applicable laws and regulations. The authors assume no liability for misuse.

## 🙏 Acknowledgments

- **Raspberry Pi Foundation** - Hardware platform
- **Kali Linux Team** - Security-focused OS
- **MediaTek** - MT7612U chipset and drivers
- **Suricata Team** - Intrusion detection system
- **Open Source Community** - Security tools and libraries
- **Cybersecurity Community** - Threat intelligence and best practices

## 📞 Support

- **Documentation**: Check docs/ directory first
- **Issues**: Use GitHub Issues for bug reports
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Report security issues privately

---

**Built for cybersecurity professionals who demand enterprise-grade security in a portable, cost-effective solution.**
