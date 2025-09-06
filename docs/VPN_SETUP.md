# 🔐 VPN Setup and Configuration Guide

## Overview

This guide provides comprehensive instructions for setting up VPN client connections on the RPi5 Secure Router, supporting both WireGuard and OpenVPN with security best practices.

## 🚀 Quick Start

### Check VPN Support
```bash
sudo ./scripts/vpn_setup.sh check
```

### Install VPN Clients
```bash
sudo ./scripts/vpn_setup.sh install
```

### Setup Configuration
```bash
# WireGuard
sudo ./scripts/vpn_setup.sh setup-wg myvpn

# OpenVPN  
sudo ./scripts/vpn_setup.sh setup-ovpn myvpn
```

## 🔧 WireGuard Configuration

### Installation
```bash
sudo apt-get install wireguard wireguard-tools
sudo modprobe wireguard
```

### Configuration File
Location: `/etc/routerpi/vpn/[config_name].conf`

```ini
[Interface]
PrivateKey = <client_private_key>
Address = 10.0.0.2/32
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = <server_public_key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

### Management Commands
```bash
# Connect
sudo wg-quick up myvpn

# Disconnect
sudo wg-quick down myvpn

# Status
sudo wg show
```

## 🔒 OpenVPN Configuration

### Installation
```bash
sudo apt-get install openvpn openvpn-systemd-resolved
```

### Configuration File
Location: `/etc/routerpi/vpn/[config_name].ovpn`

```ovpn
client
dev tun
proto udp
remote vpn.example.com 1194
cipher AES-256-GCM
auth SHA256
key-direction 1
remote-cert-tls server
tls-version-min 1.2
auth-user-pass auth.txt
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
```

### Management Commands
```bash
# Connect
sudo openvpn --config myvpn.ovpn --daemon

# Disconnect
sudo pkill openvpn

# Status
sudo systemctl status openvpn@myvpn
```

## 🛡️ Security Features

### Kill Switch
```bash
# Setup kill switch
sudo ./scripts/vpn_setup.sh kill-switch

# Enable/disable
sudo /etc/routerpi/vpn_kill_switch.sh enable
sudo /etc/routerpi/vpn_kill_switch.sh disable
```

### DNS Leak Protection
- Automatic DNS configuration through VPN
- DNS server override capability
- IPv6 leak prevention

## 📊 Monitoring and Testing

### Connection Status
```bash
# Check VPN status
sudo ./scripts/vpn_setup.sh status

# Test public IP
curl -s http://httpbin.org/ip

# DNS leak test
dig +short myip.opendns.com @resolver1.opendns.com
```

### Performance Testing
```bash
# Speed test
speedtest-cli

# Latency test
ping -c 10 8.8.8.8

# Traffic monitoring
sudo iftop -i wg0  # WireGuard
sudo iftop -i tun0 # OpenVPN
```

## 🛠️ Troubleshooting

### WireGuard Issues
```bash
# Check interface
sudo wg show

# Verify config
sudo wg showconf wg0

# Test server connectivity
nc -u vpn.example.com 51820
```

### OpenVPN Issues
```bash
# Check logs
sudo journalctl -u openvpn@myvpn -f

# Verify certificates
openssl verify -CAfile ca.crt client.crt

# Test server
telnet vpn.example.com 1194
```

## 🔐 Best Practices

1. **Use strong authentication** - Certificates + pre-shared keys
2. **Enable kill switch** - Prevent traffic leaks
3. **Test regularly** - Check for DNS/IPv6 leaks
4. **Monitor performance** - Ensure optimal speeds
5. **Rotate keys** - Update credentials periodically
6. **Choose good servers** - Select reputable VPN providers

For detailed configuration examples and advanced setups, refer to the script documentation and configuration templates.