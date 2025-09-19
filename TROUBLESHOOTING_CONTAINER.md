# Container Environment Troubleshooting Guide

## Overview
This guide helps resolve common issues when running the secure router in container environments without systemd.

## Common Issues and Solutions

### 1. dnsmasq.service Errors

**Problem**: "System has not been booted with systemd as init system"

**Solution**: Use the container-friendly script:
```bash
sudo ./router_pi_container.sh start
```

This script starts services directly without systemd.

### 2. wlan0 Interface Not Coming Up

**Problem**: wlan0 interface fails to go up or stays in "down" state

**Solutions**:

1. **Run the interface fix script**:
   ```bash
   sudo ./scripts/fix_wlan0.sh wlan0
   ```

2. **Manual interface reset**:
   ```bash
   # Kill conflicting processes
   sudo pkill wpa_supplicant
   sudo pkill dhclient
   sudo pkill dhcpcd
   
   # Reset the interface
   sudo ip link set wlan0 down
   sudo ip addr flush dev wlan0
   sleep 2
   sudo ip link set wlan0 up
   ```

3. **Check for alternative interfaces**:
   ```bash
   ls /sys/class/net/
   # Look for wlan1, wlp*, or wlx* interfaces
   ```

### 3. Missing Network Tools

**Problem**: Commands like `ip`, `iw`, `rfkill` not found

**Solution**: The container script includes fallback methods using:
- `/sys/class/net/` filesystem
- `ifconfig` (if available)
- Direct sysfs manipulation

### 4. dnsmasq Configuration Errors

**Problem**: dnsmasq fails to start due to configuration issues

**Solutions**:

1. **Use simplified configuration**:
   ```bash
   sudo dnsmasq -C /workspace/configs/dnsmasq_simple.conf --test
   ```

2. **Common fixes**:
   - Remove `bind-dynamic` if causing issues
   - Ensure interface exists before starting
   - Check for port 53 conflicts: `sudo lsof -i :53`

3. **Start dnsmasq manually for debugging**:
   ```bash
   sudo dnsmasq -C /workspace/configs/dnsmasq_simple.conf -d
   ```

### 5. hostapd Startup Issues

**Problem**: hostapd fails to start or configure AP

**Solutions**:

1. **Check interface capabilities**:
   ```bash
   # Test if interface supports AP mode
   sudo iw dev wlan0 interface add test_ap type __ap
   sudo iw dev test_ap del
   ```

2. **Use 2.4GHz instead of 5GHz**:
   ```bash
   USE_5GHZ=false sudo ./router_pi_container.sh start
   ```

3. **Debug hostapd**:
   ```bash
   sudo hostapd -dd /tmp/hostapd.conf
   ```

## Step-by-Step Troubleshooting Process

1. **Check system environment**:
   ```bash
   # Check if in container
   ls /.dockerenv
   
   # Check available commands
   which ip iw ifconfig
   
   # List network interfaces
   ls /sys/class/net/
   ```

2. **Fix wlan0 interface**:
   ```bash
   sudo ./scripts/fix_wlan0.sh wlan0
   ```

3. **Start router with debug output**:
   ```bash
   sudo ./router_pi_container.sh start
   ```

4. **Check service status**:
   ```bash
   sudo ./router_pi_container.sh status
   ```

5. **View logs**:
   ```bash
   sudo ./router_pi_container.sh logs
   ```

## Alternative Approaches

### Using a Different Interface

If wlan0 doesn't work, try another interface:

```bash
# List wireless interfaces
ls /sys/class/net/*/wireless | cut -d/ -f5

# Use a different interface
LAN_IFACE=wlan1 sudo ./router_pi_container.sh start
```

### Manual Service Start

Start services manually for more control:

```bash
# Configure interface
sudo ip addr add 10.5.5.1/24 dev wlan0
sudo ip link set wlan0 up

# Start dnsmasq
sudo dnsmasq -C /workspace/configs/dnsmasq_simple.conf

# Start hostapd
sudo hostapd /tmp/hostapd.conf
```

### Using NetworkManager (if available)

If NetworkManager is installed but causing conflicts:

```bash
# Set interface to unmanaged
sudo nmcli device set wlan0 managed no

# Or stop NetworkManager completely
sudo systemctl stop NetworkManager
```

## Monitoring and Debugging

### Check Interface State
```bash
# Interface operstate
cat /sys/class/net/wlan0/operstate

# Interface flags
cat /sys/class/net/wlan0/flags

# Carrier status
cat /sys/class/net/wlan0/carrier
```

### Monitor Service Output
```bash
# Watch dnsmasq logs
tail -f /tmp/routerpi/logs/dnsmasq.out

# Watch hostapd logs
tail -f /tmp/routerpi/logs/hostapd.out
```

### Test Configuration Files
```bash
# Test dnsmasq config
sudo dnsmasq --test -C /tmp/dnsmasq.conf

# Test hostapd config
sudo hostapd -t /tmp/hostapd.conf
```

## Quick Reset

If things go wrong, reset everything:

```bash
# Stop router
sudo ./router_pi_container.sh stop

# Kill all related processes
sudo pkill dnsmasq
sudo pkill hostapd
sudo pkill wpa_supplicant

# Reset interfaces
sudo ip link set wlan0 down
sudo ip addr flush dev wlan0

# Clear temporary files
sudo rm -rf /tmp/routerpi

# Start fresh
sudo ./router_pi_container.sh start
```

## Getting Help

If issues persist:

1. Run the diagnostic script:
   ```bash
   sudo ./scripts/diagnose_network.sh
   ```

2. Check kernel messages:
   ```bash
   dmesg | grep -E "wlan|wifi|80211"
   ```

3. Verify hardware:
   ```bash
   lsusb | grep -i wireless
   ```

4. Check for firmware issues:
   ```bash
   dmesg | grep -i firmware
   ```