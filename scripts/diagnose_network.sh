#!/bin/bash
#===============================================================================
# Network Diagnostics Script for Secure Travel Router
# Helps diagnose interface and service issues
#===============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Network Interface Diagnostics ==="
echo

# Check for required commands
echo "Checking required commands..."
for cmd in ip iw nmcli hostapd dnsmasq; do
    if command -v $cmd >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $cmd found: $(which $cmd)"
    else
        echo -e "${RED}✗${NC} $cmd not found"
    fi
done
echo

# List all network interfaces
echo "Network interfaces:"
if command -v ip >/dev/null 2>&1; then
    ip link show | grep -E "^[0-9]+: " | while read line; do
        iface=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        state=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "unknown")
        if [[ -d "/sys/class/net/$iface/wireless" ]]; then
            echo -e "  ${YELLOW}$iface${NC} (wireless) - state: $state"
            # Check if managed by NetworkManager
            if command -v nmcli >/dev/null 2>&1; then
                managed=$(nmcli device show "$iface" 2>/dev/null | grep -i "general.state" | awk '{print $2}' || echo "unknown")
                echo "    NetworkManager: $managed"
            fi
            # Check wireless capabilities
            if command -v iw >/dev/null 2>&1; then
                iw dev "$iface" info 2>/dev/null | grep -E "(type|channel|addr)" | sed 's/^/    /'
            fi
        else
            echo -e "  $iface (wired) - state: $state"
        fi
        # Show IP addresses
        ip addr show "$iface" 2>/dev/null | grep "inet " | sed 's/^/    /'
    done
else
    echo -e "${RED}ip command not available${NC}"
fi
echo

# Check for conflicting processes
echo "Checking for conflicting processes..."
for process in wpa_supplicant NetworkManager dhclient dhcpcd; do
    if pgrep -x "$process" >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠${NC} $process is running (PID: $(pgrep -x "$process" | tr '\n' ' '))"
        pgrep -fa "$process" | sed 's/^/    /'
    fi
done
echo

# Check dnsmasq configuration
echo "Checking dnsmasq configuration..."
if [[ -f "/etc/dnsmasq.d/router-secure.conf" ]]; then
    echo -e "${GREEN}✓${NC} Router dnsmasq config found"
    # Test configuration
    if command -v dnsmasq >/dev/null 2>&1; then
        if dnsmasq --test -C /etc/dnsmasq.d/router-secure.conf 2>&1 | grep -q "OK"; then
            echo -e "${GREEN}✓${NC} Configuration syntax is valid"
        else
            echo -e "${RED}✗${NC} Configuration has errors:"
            dnsmasq --test -C /etc/dnsmasq.d/router-secure.conf 2>&1 | sed 's/^/    /'
        fi
    fi
else
    echo -e "${YELLOW}⚠${NC} Router dnsmasq config not found"
fi

# Check for running dnsmasq
if pgrep dnsmasq >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} dnsmasq is running (PID: $(pgrep dnsmasq | tr '\n' ' '))"
else
    echo -e "${RED}✗${NC} dnsmasq is not running"
fi
echo

# Check hostapd configuration
echo "Checking hostapd configuration..."
if [[ -f "/etc/hostapd/hostapd.conf" ]]; then
    echo -e "${GREEN}✓${NC} Hostapd config found"
    # Extract key information
    echo "  SSID: $(grep "^ssid=" /etc/hostapd/hostapd.conf | cut -d= -f2)"
    echo "  Interface: $(grep "^interface=" /etc/hostapd/hostapd.conf | cut -d= -f2)"
    echo "  Channel: $(grep "^channel=" /etc/hostapd/hostapd.conf | cut -d= -f2)"
else
    echo -e "${YELLOW}⚠${NC} Hostapd config not found"
fi

# Check for running hostapd
if pgrep hostapd >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} hostapd is running (PID: $(pgrep hostapd | tr '\n' ' '))"
else
    echo -e "${RED}✗${NC} hostapd is not running"
fi
echo

# Check iptables rules
echo "Checking firewall rules..."
if command -v iptables >/dev/null 2>&1; then
    nat_rules=$(iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -c MASQUERADE || echo 0)
    forward_rules=$(iptables -L FORWARD -n 2>/dev/null | grep -c ACCEPT || echo 0)
    if [[ $nat_rules -gt 0 ]]; then
        echo -e "${GREEN}✓${NC} NAT rules configured ($nat_rules MASQUERADE rules)"
    else
        echo -e "${RED}✗${NC} No NAT rules found"
    fi
    if [[ $forward_rules -gt 0 ]]; then
        echo -e "${GREEN}✓${NC} FORWARD rules configured ($forward_rules ACCEPT rules)"
    else
        echo -e "${RED}✗${NC} No FORWARD rules found"
    fi
else
    echo -e "${RED}iptables command not available${NC}"
fi
echo

# Check IP forwarding
echo "Checking IP forwarding..."
if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
    forward_status=$(cat /proc/sys/net/ipv4/ip_forward)
    if [[ "$forward_status" == "1" ]]; then
        echo -e "${GREEN}✓${NC} IP forwarding is enabled"
    else
        echo -e "${RED}✗${NC} IP forwarding is disabled"
    fi
fi
echo

# Check for wireless regulatory domain
echo "Checking wireless regulatory domain..."
if command -v iw >/dev/null 2>&1; then
    reg_domain=$(iw reg get 2>/dev/null | grep "country" | head -1 || echo "Not set")
    echo "  Current: $reg_domain"
fi
echo

# Recommendations
echo "=== Recommendations ==="
if pgrep -x NetworkManager >/dev/null 2>&1; then
    echo "• NetworkManager is running. Consider stopping it or setting interfaces to unmanaged:"
    echo "  sudo systemctl stop NetworkManager"
    echo "  OR"
    echo "  nmcli device set <interface> managed no"
fi

if pgrep -x wpa_supplicant >/dev/null 2>&1; then
    echo "• wpa_supplicant is running. Stop it before starting the router:"
    echo "  sudo pkill wpa_supplicant"
fi

echo
echo "To test a specific wireless interface for AP mode capability:"
echo "  sudo iw dev <interface> interface add test_ap type __ap"
echo "  sudo iw dev test_ap del"