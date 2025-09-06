# 🌐 Network Configuration Guide

## Overview

This document provides detailed information about the network configuration and optimization for the RPi5 Secure Router, including interface management, routing, and performance tuning.

## 📡 Network Architecture

### Interface Layout

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Internet      │◄──►│  WAN Interface  │◄──►│  RPi5 Router    │
│                 │    │  (eth0/wlan1)   │    │                 │
└─────────────────┘    └─────────────────┘    │  ┌─────────────┐ │
                                              │  │   Bridge    │ │
┌─────────────────┐    ┌─────────────────┐    │  │  (optional) │ │
│  Client Devices │◄──►│  LAN Interface  │◄──►│  └─────────────┘ │
│                 │    │ (wlan0/MT7612U) │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Default Network Configuration

| Component | Default Value | Description |
|-----------|--------------|-------------|
| **WAN Interface** | `eth0` (auto-detected) | Internet connection |
| **LAN Interface** | `wlan0` (MT7612U) | Client access point |
| **Router IP** | `192.168.8.1/24` | Router management interface |
| **DHCP Range** | `192.168.8.10-50` | Client IP assignment range |
| **DNS Servers** | `1.1.1.1, 9.9.9.9, 8.8.8.8` | Upstream DNS resolution |

## 🔧 Interface Configuration

### WAN Interface Setup

The WAN interface is automatically detected and configured:

```bash
# Auto-detection
WAN_IFACE=$(ip route | awk '/default/ {print $5; exit}')

# Manual configuration
WAN_IFACE="eth0"  # For Ethernet
WAN_IFACE="wlan1" # For secondary WiFi
```

### LAN Interface (MT7612U) Configuration

```bash
# Interface configuration
LAN_IFACE="wlan0"
AP_ADDR="192.168.8.1/24"

# Configure for AP mode
sudo ip link set $LAN_IFACE down
sudo iw dev $LAN_IFACE set type __ap
sudo ip addr add $AP_ADDR dev $LAN_IFACE
sudo ip link set $LAN_IFACE up
```

### Network Namespace Isolation (Advanced)

For enhanced security, you can run the router in a network namespace:

```bash
# Create network namespace
sudo ip netns add router_ns

# Move interfaces to namespace
sudo ip link set $LAN_IFACE netns router_ns

# Configure within namespace
sudo ip netns exec router_ns ip addr add $AP_ADDR dev $LAN_IFACE
sudo ip netns exec router_ns ip link set $LAN_IFACE up
```

## 🛣️ Routing Configuration

### Default Route Management

```bash
# Check current default route
ip route show default

# Add default route (if needed)
sudo ip route add default via $GATEWAY_IP dev $WAN_IFACE

# Route priorities
sudo ip route add default via $PRIMARY_GW dev $WAN_IFACE metric 100
sudo ip route add default via $BACKUP_GW dev $BACKUP_IFACE metric 200
```

### Policy-Based Routing

For advanced traffic management:

```bash
# Create routing tables
echo "100 wan_table" >> /etc/iproute2/rt_tables
echo "200 vpn_table" >> /etc/iproute2/rt_tables

# Route specific traffic through VPN
sudo ip rule add from 192.168.8.0/24 table vpn_table
sudo ip route add default via $VPN_GATEWAY table vpn_table
```

### Load Balancing (Multi-WAN)

```bash
# Setup load balancing across multiple WAN interfaces
sudo ip route add default scope global \
  nexthop via $WAN1_GW dev $WAN1_IFACE weight 1 \
  nexthop via $WAN2_GW dev $WAN2_IFACE weight 1
```

## 📶 WiFi Configuration

### Channel Selection

#### 2.4GHz Channels
- **Recommended**: 1, 6, 11 (non-overlapping)
- **Avoid**: Channels 2-5, 7-10, 12-14 (overlapping)

#### 5GHz Channels
- **Low Band**: 36, 40, 44, 48 (indoor use)
- **Mid Band**: 52, 56, 60, 64 (DFS required)
- **High Band**: 149, 153, 157, 161 (outdoor use)

### Channel Width Optimization

```bash
# 2.4GHz: 20MHz for compatibility, 40MHz for performance
HT_CAPAB="[HT40+][SHORT-GI-20][SHORT-GI-40]"

# 5GHz: 80MHz for maximum performance
VHT_CAPAB="[MAX-MPDU-11454][SHORT-GI-80][TX-STBC-2BY1]"
```

### Regulatory Domain

```bash
# Set regulatory domain
sudo iw reg set US  # United States
sudo iw reg set EU  # European Union
sudo iw reg set JP  # Japan

# Check current setting
iw reg get
```

## 🔍 DHCP and DNS Configuration

### DHCP Server Configuration

```bash
# Basic DHCP range
dhcp-range=192.168.8.10,192.168.8.50,12h

# Static IP assignments
dhcp-host=aa:bb:cc:dd:ee:ff,192.168.8.100,laptop
dhcp-host=11:22:33:44:55:66,192.168.8.101,phone

# DHCP options
dhcp-option=option:router,192.168.8.1
dhcp-option=option:dns-server,192.168.8.1
dhcp-option=option:ntp-server,192.168.8.1
dhcp-option=option:mtu,1500
```

### DNS Configuration

```bash
# Upstream DNS servers
server=1.1.1.1#53      # Cloudflare
server=1.0.0.1#53      # Cloudflare Secondary
server=9.9.9.9#53      # Quad9
server=149.112.112.112#53  # Quad9 Secondary

# Local DNS entries
address=/router.local/192.168.8.1
address=/gateway.local/192.168.8.1
```

## 🚀 Performance Optimization

### Network Buffer Tuning

```bash
# Increase buffer sizes
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf
```

### TCP Optimization

```bash
# TCP congestion control
echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf

# TCP window scaling
echo 'net.ipv4.tcp_window_scaling = 1' >> /etc/sysctl.conf

# TCP fast open
echo 'net.ipv4.tcp_fastopen = 3' >> /etc/sysctl.conf
```

### WiFi Performance Tuning

```bash
# Disable power management
sudo iw dev $LAN_IFACE set power_save off

# Set transmission power (regulatory limits apply)
sudo iw dev $LAN_IFACE set txpower fixed 2000  # 20dBm

# Optimize queue discipline
sudo tc qdisc add dev $LAN_IFACE root fq_codel
```

## 🔧 Quality of Service (QoS)

### Traffic Shaping

```bash
# Create QoS classes
sudo tc qdisc add dev $WAN_IFACE root handle 1: htb default 30

# High priority (VoIP, SSH)
sudo tc class add dev $WAN_IFACE parent 1: classid 1:10 htb rate 2mbit ceil 5mbit
sudo tc filter add dev $WAN_IFACE protocol ip parent 1:0 prio 1 u32 match ip dport 22 0xffff flowid 1:10

# Medium priority (Web browsing)
sudo tc class add dev $WAN_IFACE parent 1: classid 1:20 htb rate 5mbit ceil 10mbit
sudo tc filter add dev $WAN_IFACE protocol ip parent 1:0 prio 2 u32 match ip dport 80 0xffff flowid 1:20

# Low priority (bulk transfers)
sudo tc class add dev $WAN_IFACE parent 1: classid 1:30 htb rate 1mbit ceil 8mbit
```

### Bandwidth Limiting

```bash
# Limit per-client bandwidth
iptables -A FORWARD -s 192.168.8.0/24 -m hashlimit \
  --hashlimit-above 5mb/s --hashlimit-burst 10mb \
  --hashlimit-mode srcip --hashlimit-name bw_limit \
  -j DROP
```

## 📊 Network Monitoring

### Interface Statistics

```bash
# Real-time interface monitoring
watch -n 1 'cat /proc/net/dev'

# Detailed interface statistics
ip -s link show $LAN_IFACE

# Traffic analysis
iftop -i $LAN_IFACE
nethogs $LAN_IFACE
```

### Connection Tracking

```bash
# Active connections
ss -tuln
netstat -tuln

# Connection states
cat /proc/net/nf_conntrack | wc -l

# Per-IP connection count
cat /proc/net/nf_conntrack | cut -d' ' -f7 | cut -d'=' -f2 | sort | uniq -c | sort -nr
```

### Bandwidth Monitoring

```bash
# vnStat configuration
sudo vnstat -u -i $WAN_IFACE
sudo vnstat -u -i $LAN_IFACE

# Real-time bandwidth
vnstat -l -i $WAN_IFACE

# Daily/monthly statistics
vnstat -d -i $WAN_IFACE
vnstat -m -i $WAN_IFACE
```

## 🔗 Bridge Configuration (Optional)

### Creating a Bridge Interface

```bash
# Create bridge
sudo ip link add name br0 type bridge

# Add interfaces to bridge
sudo ip link set $LAN_IFACE master br0
sudo ip link set eth1 master br0  # Additional interface

# Configure bridge
sudo ip addr add 192.168.8.1/24 dev br0
sudo ip link set br0 up

# Enable STP (Spanning Tree Protocol)
sudo ip link set br0 type bridge stp_state 1
```

### VLAN Configuration

```bash
# Create VLAN interfaces
sudo ip link add link $LAN_IFACE name $LAN_IFACE.100 type vlan id 100
sudo ip link add link $LAN_IFACE name $LAN_IFACE.200 type vlan id 200

# Configure VLAN IPs
sudo ip addr add 192.168.100.1/24 dev $LAN_IFACE.100
sudo ip addr add 192.168.200.1/24 dev $LAN_IFACE.200

# Bring up VLAN interfaces
sudo ip link set $LAN_IFACE.100 up
sudo ip link set $LAN_IFACE.200 up
```

## 🛠️ Troubleshooting Network Issues

### Common Network Problems

#### No Internet Connectivity
```bash
# Check WAN interface
ip addr show $WAN_IFACE

# Check default route
ip route show default

# Test gateway
ping $(ip route | awk '/default/ {print $3}')

# Check DNS
nslookup google.com
```

#### Poor Performance
```bash
# Check interface errors
ip -s link show $LAN_IFACE

# Monitor CPU usage
top -n 1 | grep hostapd

# Check for interference
iwlist $LAN_IFACE scan | grep -E "(ESSID|Channel|Quality)"
```

#### DHCP Issues
```bash
# Check DHCP leases
cat /var/lib/dhcp/dhcpd.leases

# Monitor DHCP requests
sudo tcpdump -i $LAN_IFACE port 67 or port 68

# Restart DHCP service
sudo systemctl restart dnsmasq
```

### Network Diagnostic Tools

```bash
# Comprehensive network test
sudo ./scripts/network_diag.sh full

# Connectivity test
sudo ./scripts/network_diag.sh connectivity

# Performance analysis
sudo ./scripts/network_diag.sh performance

# Real-time monitoring
sudo ./scripts/network_diag.sh monitor
```

## 📚 Advanced Configuration Examples

### Multi-SSID Setup

```bash
# Primary SSID (secure)
interface=wlan0
ssid=SecureTravel_Main
wpa=2
wpa_passphrase=secure_password

# Guest SSID (isolated)
bss=wlan0_1
ssid=SecureTravel_Guest
wpa=2
wpa_passphrase=guest_password
ap_isolate=1
```

### Captive Portal Configuration

```bash
# Redirect HTTP to captive portal
iptables -t nat -A PREROUTING -i $LAN_IFACE -p tcp --dport 80 \
  -j DNAT --to-destination 192.168.8.1:8080

# Portal exceptions
iptables -t nat -I PREROUTING -i $LAN_IFACE -s 192.168.8.100 -j ACCEPT
```

### Mesh Network Configuration

```bash
# Enable 802.11s mesh
iw dev $LAN_IFACE set type mp
iw dev $LAN_IFACE mesh join mesh_network

# Configure mesh parameters
iw dev $LAN_IFACE set mesh_param mesh_retry_timeout 100
iw dev $LAN_IFACE set mesh_param mesh_confirm_timeout 100
```

This networking guide provides comprehensive configuration options for optimizing your RPi5 Secure Router for various deployment scenarios and performance requirements.