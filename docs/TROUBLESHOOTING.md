# 🔧 Troubleshooting Guide

## Quick Diagnostics

### Run Full Diagnostic
```bash
sudo ./scripts/network_diag.sh full
```

### Check Router Status
```bash
sudo ./router_pi_secure.sh status
```

## 📡 MT7612U Adapter Issues

### Adapter Not Detected
**Symptoms**: No wireless interface, `lsusb` doesn't show adapter
```bash
# Check USB detection
lsusb | grep 0e8d:7612

# Check driver loading
lsmod | grep mt76

# Reset adapter
sudo ./router_pi_secure.sh reset
sudo ./scripts/mt7612u_monitor.sh reset

# Check adapter health
sudo ./scripts/mt7612u_monitor.sh check
```

**Solutions**:
1. Unplug and replug the adapter
2. Try different USB port
3. Check power supply (adapter needs sufficient power)
4. Reload driver: `sudo modprobe -r mt76x2u && sudo modprobe mt76x2u`

### Adapter Detected but No Interface
```bash
# Check interface creation
ip link show

# Check for errors in dmesg
dmesg | tail -50 | grep -i mt76

# Manual interface creation
sudo iw phy phy0 interface add wlan0 type __ap
```

### Poor Performance or Disconnections
```bash
# Monitor adapter health
sudo ./scripts/mt7612u_monitor.sh monitor

# Check for USB errors
dmesg | grep -i usb | tail -20

# Check power management
sudo iw dev wlan0 set power_save off
```

## 📶 WiFi/Hostapd Issues

### No WiFi Network Visible
**Check hostapd status**:
```bash
sudo systemctl status hostapd
sudo journalctl -u hostapd -n 50
```

**Common fixes**:
```bash
# Restart hostapd
sudo systemctl restart hostapd

# Check configuration
sudo hostapd -dd /etc/hostapd/hostapd.conf

# Check interface status
ip link show wlan0
sudo iw dev wlan0 info
```

### WiFi Network Visible but Can't Connect
**Check authentication**:
```bash
# Verify password
cat /run/routerpi/wifi_password

# Check WPA configuration
grep -E "(wpa|auth)" /etc/hostapd/hostapd.conf

# Monitor hostapd logs during connection attempt
sudo journalctl -u hostapd -f
```

### Clients Connect but No Internet
```bash
# Check DHCP
sudo systemctl status dnsmasq
sudo journalctl -u dnsmasq -n 20

# Check IP assignment
sudo dhcp-lease-list 2>/dev/null || cat /var/lib/dhcp/dhcpd.leases

# Check NAT rules
sudo iptables -t nat -L POSTROUTING -v
```

## 🌐 Network Connectivity Issues

### No Internet Access
**Basic connectivity test**:
```bash
# Check interfaces
ip addr show

# Check routing
ip route show

# Test gateway
ping $(ip route | awk '/default/ {print $3}')

# Test DNS
nslookup google.com
```

**Advanced diagnostics**:
```bash
# Full connectivity test
sudo ./scripts/network_diag.sh connectivity

# Check firewall rules
sudo iptables -L -n -v
sudo iptables -t nat -L -n -v

# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward
```

### Slow Internet or High Latency
```bash
# Speed test
sudo ./scripts/network_diag.sh speed

# Check interface statistics
cat /proc/net/dev

# Monitor traffic
sudo ./scripts/network_diag.sh monitor

# Check for congestion
ss -tuln
```

## 🔥 Firewall Issues

### Locked Out (Can't SSH)
**Emergency access**:
1. Physical console access required
2. Or reboot the Pi to reset iptables rules

**Reset firewall**:
```bash
# Emergency flush (console access)
sudo iptables -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Restart router
sudo ./router_pi_secure.sh stop
sudo ./router_pi_secure.sh start
```

### Services Blocked
```bash
# Check specific rules
sudo iptables -L INPUT -n -v | grep :PORT

# Temporarily allow service
sudo iptables -I INPUT -p tcp --dport PORT -j ACCEPT

# Check logs for blocks
journalctl | grep "ROUTER-DROP"
```

## 🔍 DNS Issues

### DNS Resolution Fails
```bash
# Check dnsmasq status
sudo systemctl status dnsmasq

# Test DNS directly
dig @192.168.8.1 google.com
nslookup google.com 192.168.8.1

# Check upstream DNS
dig @1.1.1.1 google.com

# Restart DNS
sudo systemctl restart dnsmasq
```

### DNS Leaks
```bash
# Check current DNS
cat /etc/resolv.conf

# Test for leaks
sudo ./scripts/vpn_setup.sh status

# Check DNS configuration
cat /etc/dnsmasq.d/router-secure.conf
```

## ⚡ Performance Issues

### High CPU Usage
```bash
# Check processes
top -n 1
ps aux --sort=-%cpu | head -10

# Check router resources
sudo ./router_pi_secure.sh status

# Monitor system
sudo ./scripts/network_diag.sh performance
```

### Memory Issues
```bash
# Check memory usage
free -h
cat /proc/meminfo

# Check for memory leaks
ps aux --sort=-%mem | head -10

# Clear caches if needed
sudo sync && sudo sysctl -w vm.drop_caches=3
```

### Temperature Issues
```bash
# Check temperature
vcgencmd measure_temp

# Check throttling
vcgencmd get_throttled

# Monitor temperature
watch -n 1 vcgencmd measure_temp
```

## 🔒 Security Issues

### Security Audit Failures
```bash
# Run security audit
sudo ./router_pi_secure.sh audit

# Check specific categories
sudo ./scripts/security_audit.sh firewall
sudo ./scripts/security_audit.sh services
sudo ./scripts/security_audit.sh system
```

### Blocked IPs Management
```bash
# View blocked IPs
cat /run/routerpi/blocked_ips

# Manually block IP
sudo iptables -I INPUT -s MALICIOUS_IP -j DROP

# Manually unblock IP
sudo iptables -D INPUT -s MALICIOUS_IP -j DROP
sed -i "/^MALICIOUS_IP /d" /run/routerpi/blocked_ips
```

### Log Analysis
```bash
# Security events
tail -f /var/log/routerpi/security.log

# Traffic logs
tail -f /var/log/routerpi/traffic.log

# System logs
journalctl -f | grep routerpi

# Firewall logs
journalctl -f | grep "ROUTER-DROP"
```

## 🚨 Emergency Procedures

### Complete Reset
```bash
# Stop router
sudo ./router_pi_secure.sh stop

# Reset network configuration
sudo ip addr flush dev wlan0
sudo ip link set wlan0 down

# Clear state files
sudo rm -rf /run/routerpi/*

# Restart
sudo ./router_pi_secure.sh start
```

### Factory Reset
```bash
# Stop all services
sudo systemctl stop hostapd dnsmasq

# Remove configurations
sudo rm -f /etc/hostapd/hostapd.conf
sudo rm -f /etc/dnsmasq.d/router-secure.conf

# Clear logs
sudo rm -rf /var/log/routerpi/*

# Reinstall
sudo ./install.sh
```

### Recovery Mode
If router becomes unresponsive:

1. **Physical access**: Connect keyboard/monitor to Pi
2. **Network access**: Try SSH from different network
3. **USB console**: Use USB-to-serial adapter
4. **SD card**: Remove SD card and edit files directly

## 📋 Common Error Messages

### "MT7612U not detected"
- Check USB connection
- Verify power supply
- Try different USB port
- Check driver installation

### "Interface wlan0 not found"
- Adapter not detected
- Driver not loaded
- Interface naming conflict

### "hostapd failed to start"
- Configuration error
- Interface not available
- Channel conflict
- Regulatory domain issue

### "No DHCP leases"
- dnsmasq not running
- Configuration error
- Interface binding issue
- Firewall blocking DHCP

### "NAT not working"
- IP forwarding disabled
- iptables rules missing
- Interface configuration error
- Routing table issues

## 🛠️ Advanced Debugging

### Enable Debug Logging
```bash
# hostapd debug
sudo hostapd -dd /etc/hostapd/hostapd.conf

# dnsmasq debug
sudo dnsmasq --no-daemon --log-queries --log-dhcp

# iptables logging
sudo iptables -I INPUT -j LOG --log-prefix "DEBUG-INPUT: "
sudo iptables -I FORWARD -j LOG --log-prefix "DEBUG-FORWARD: "
```

### Packet Capture
```bash
# Capture on wireless interface
sudo tcpdump -i wlan0 -w /tmp/wlan0.pcap

# Capture DHCP traffic
sudo tcpdump -i wlan0 port 67 or port 68

# Capture DNS traffic
sudo tcpdump -i wlan0 port 53
```

### Network Tracing
```bash
# Trace route to internet
traceroute 8.8.8.8

# Check ARP table
arp -a

# Monitor connections
watch -n 1 'ss -tuln'
```

## 📞 Getting Help

### Log Collection
Before seeking help, collect these logs:
```bash
# Create debug archive
mkdir -p /tmp/router_debug
sudo ./router_pi_secure.sh status > /tmp/router_debug/status.txt
sudo ./scripts/network_diag.sh full > /tmp/router_debug/network_diag.txt
sudo ./scripts/security_audit.sh full > /tmp/router_debug/security_audit.txt
sudo journalctl -u hostapd > /tmp/router_debug/hostapd.log
sudo journalctl -u dnsmasq > /tmp/router_debug/dnsmasq.log
sudo iptables -L -n -v > /tmp/router_debug/iptables.txt
sudo iptables -t nat -L -n -v > /tmp/router_debug/nat.txt
dmesg > /tmp/router_debug/dmesg.txt
tar -czf router_debug.tar.gz -C /tmp router_debug/
```

### System Information
```bash
# Hardware info
cat /proc/cpuinfo | head -20
cat /proc/meminfo | head -10
lsusb
lspci

# Software info
uname -a
hostapd -v
dnsmasq --version
iptables --version
```

Remember: Always maintain backups of working configurations and document any changes made during troubleshooting.
