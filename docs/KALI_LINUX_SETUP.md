# Kali Linux Router Setup Guide

## Overview
This guide addresses common issues when running the secure router on Kali Linux, particularly with dnsmasq service errors and wlan0 interface configuration.

## Quick Fix for Common Issues

If you're experiencing dnsmasq service errors or wlan0 interface issues, run:

```bash
sudo ./scripts/fix_kali_network.sh wlan0
```

This script will:
- Configure NetworkManager to ignore your wireless interface
- Stop interfering services (wpa_supplicant, dhclient, etc.)
- Reset and prepare the wireless interface
- Apply Kali-specific optimizations
- Fix dnsmasq service configuration

## Common Issues and Solutions

### 1. dnsmasq Service Startup Errors

**Symptoms:**
- "Failed to start dnsmasq.service"
- "Address already in use" errors
- Service fails immediately after starting

**Solutions:**

1. **Check for conflicts:**
   ```bash
   # Check what's using port 53
   sudo lsof -i :53
   
   # Check if another dnsmasq instance is running
   ps aux | grep dnsmasq
   ```

2. **Fix dnsmasq configuration:**
   ```bash
   # Create dnsmasq.d directory if missing
   sudo mkdir -p /etc/dnsmasq.d
   
   # Test configuration
   sudo dnsmasq --test -C /etc/dnsmasq.d/router-secure.conf
   ```

3. **Clear systemd failures:**
   ```bash
   sudo systemctl reset-failed dnsmasq
   sudo systemctl daemon-reload
   ```

### 2. wlan0 Interface Not Coming Up

**Symptoms:**
- Interface stays in "down" state
- "RTNETLINK answers: Operation not possible due to RF-kill"
- Interface resets when trying to configure

**Solutions:**

1. **NetworkManager Interference:**
   ```bash
   # Set interface to unmanaged
   sudo nmcli device set wlan0 managed no
   
   # Or disable NetworkManager completely
   sudo systemctl stop NetworkManager
   ```

2. **RF-Kill Issues:**
   ```bash
   # Check rfkill status
   rfkill list
   
   # Unblock all wireless
   sudo rfkill unblock all
   ```

3. **Driver/Module Issues:**
   ```bash
   # Check loaded modules
   lsmod | grep -E "80211|wifi|wlan"
   
   # Reload wireless modules (example for common chips)
   sudo modprobe -r iwlwifi  # Intel
   sudo modprobe -r ath9k    # Atheros
   sudo modprobe -r rt2800usb # Ralink USB
   
   # Reload
   sudo modprobe iwlwifi
   ```

### 3. Kali-Specific Configuration

**NetworkManager Configuration:**

Create `/etc/NetworkManager/conf.d/99-unmanaged-devices.conf`:
```ini
[keyfile]
unmanaged-devices=interface-name:wlan0
```

**Power Management:**
```bash
# Disable power saving
sudo iw dev wlan0 set power_save off
```

**Regulatory Domain:**
```bash
# Set regulatory domain
sudo iw reg set US
```

## Step-by-Step Setup Process

### 1. Prepare the System

```bash
# Update system
sudo apt update
sudo apt install hostapd dnsmasq iptables iw wireless-tools

# Stop and disable conflicting services
sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant
```

### 2. Fix Network Configuration

```bash
# Run the Kali fix script
sudo ./scripts/fix_kali_network.sh wlan0
```

### 3. Start the Router

```bash
# Start router service
sudo ./router_pi_secure.sh start

# Check status
sudo ./router_pi_secure.sh status
```

### 4. Verify Operation

```bash
# Check services
sudo systemctl status dnsmasq
sudo systemctl status hostapd

# Check interface
ip addr show wlan0

# Check iptables rules
sudo iptables -t nat -L -v
```

## Advanced Troubleshooting

### Debug Mode Start

Start services manually for debugging:

```bash
# Stop all services
sudo ./router_pi_secure.sh stop

# Configure interface manually
sudo ip link set wlan0 down
sudo ip addr flush dev wlan0
sudo ip addr add 10.5.5.1/24 dev wlan0
sudo ip link set wlan0 up

# Start dnsmasq in debug mode
sudo dnsmasq -C /etc/dnsmasq.d/router-secure.conf -d

# In another terminal, start hostapd
sudo hostapd -d /etc/hostapd/hostapd.conf
```

### Check System Logs

```bash
# Check system logs
sudo journalctl -xe

# Check specific service logs
sudo journalctl -u dnsmasq -f
sudo journalctl -u hostapd -f

# Check kernel messages
dmesg | grep -E "wlan|80211|firmware"
```

### Alternative Interface Names

Kali may use different interface names:

```bash
# List all network interfaces
ip link show

# Look for wireless interfaces
iw dev

# Common names: wlan0, wlan1, wlp2s0, wlx00c0ca123456
```

Use a different interface:
```bash
LAN_IFACE=wlan1 sudo ./router_pi_secure.sh start
```

## Performance Optimization

### For MT7612U (Panda Wireless)

```bash
# Load module with specific parameters
sudo modprobe mt76x2u

# Check USB power
echo on | sudo tee /sys/bus/usb/devices/*/power/control
```

### Monitor Mode Conflicts

If you've been using monitor mode:

```bash
# Reset from monitor mode
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

## Security Considerations

1. **SELinux/AppArmor**: Kali typically has these disabled, but check:
   ```bash
   sestatus  # SELinux
   aa-status # AppArmor
   ```

2. **Firewall**: Ensure iptables is properly configured:
   ```bash
   sudo iptables -L -v
   sudo iptables -t nat -L -v
   ```

3. **Service Hardening**: The router script includes security features, but on Kali:
   - Ensure only necessary services are running
   - Check for open ports: `sudo netstat -tulpn`

## Quick Reference Commands

```bash
# Fix all issues at once
sudo ./scripts/fix_kali_network.sh wlan0

# Start router
sudo ./router_pi_secure.sh start

# Stop router
sudo ./router_pi_secure.sh stop

# Check status
sudo ./router_pi_secure.sh status

# Run diagnostics
sudo ./scripts/diagnose_network.sh

# Monitor traffic
sudo ./scripts/network_diag.sh monitor

# View logs
sudo journalctl -f
```

## Getting Help

If issues persist after following this guide:

1. Run full diagnostics:
   ```bash
   sudo ./scripts/diagnose_network.sh full > diagnostic_report.txt
   ```

2. Check hardware:
   ```bash
   lsusb  # For USB adapters
   lspci  # For PCIe adapters
   ```

3. Verify firmware:
   ```bash
   dmesg | grep -i firmware
   ```

Remember to check the logs in `/var/log/routerpi/` for detailed error messages.