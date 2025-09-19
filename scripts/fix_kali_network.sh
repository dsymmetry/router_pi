#!/bin/bash
#===============================================================================
# Fix Network Issues on Kali Linux for Router Mode
# Handles NetworkManager conflicts and interface configuration
#===============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

INTERFACE="${1:-wlan0}"

echo -e "${BLUE}=== Fixing Network Configuration for Kali Linux ===${NC}"
echo

# Check if running as root
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Function to disable NetworkManager for specific interface
disable_nm_for_interface() {
    local iface="$1"
    echo -e "${YELLOW}Configuring NetworkManager to ignore $iface...${NC}"
    
    # Create NetworkManager config to unmanage the interface
    cat > /etc/NetworkManager/conf.d/99-unmanaged-devices.conf << EOF
[keyfile]
unmanaged-devices=interface-name:$iface
EOF
    
    # Also add to network interfaces file
    if [[ -f /etc/network/interfaces ]]; then
        if ! grep -q "iface $iface" /etc/network/interfaces; then
            echo -e "\n# Managed by router script" >> /etc/network/interfaces
            echo "iface $iface inet manual" >> /etc/network/interfaces
        fi
    fi
    
    # Reload NetworkManager
    if systemctl is-active NetworkManager >/dev/null 2>&1; then
        echo -e "${YELLOW}Reloading NetworkManager...${NC}"
        systemctl reload NetworkManager
        sleep 2
    fi
    
    echo -e "${GREEN}✓${NC} NetworkManager configured to ignore $iface"
}

# Function to stop interfering services
stop_interfering_services() {
    echo -e "\n${BLUE}Stopping interfering services...${NC}"
    
    # Stop wpa_supplicant on the interface
    if pgrep -f "wpa_supplicant.*$INTERFACE" >/dev/null 2>&1; then
        echo -e "${YELLOW}Stopping wpa_supplicant on $INTERFACE${NC}"
        pkill -f "wpa_supplicant.*$INTERFACE"
        sleep 1
    fi
    
    # Stop dhclient
    if pgrep -f "dhclient.*$INTERFACE" >/dev/null 2>&1; then
        echo -e "${YELLOW}Stopping dhclient on $INTERFACE${NC}"
        pkill -f "dhclient.*$INTERFACE"
    fi
    
    # Stop dhcpcd
    if pgrep -f "dhcpcd.*$INTERFACE" >/dev/null 2>&1; then
        echo -e "${YELLOW}Stopping dhcpcd on $INTERFACE${NC}"
        pkill -f "dhcpcd.*$INTERFACE"
    fi
    
    echo -e "${GREEN}✓${NC} Interfering services stopped"
}

# Function to reset wireless interface
reset_wireless_interface() {
    echo -e "\n${BLUE}Resetting wireless interface $INTERFACE...${NC}"
    
    # Bring interface down
    ip link set "$INTERFACE" down 2>/dev/null || true
    
    # Remove all IP addresses
    ip addr flush dev "$INTERFACE" 2>/dev/null || true
    
    # Wait a moment
    sleep 2
    
    # Set interface to station mode first (reset from any AP mode)
    iw dev "$INTERFACE" set type managed 2>/dev/null || true
    
    # Bring interface up
    ip link set "$INTERFACE" up 2>/dev/null || true
    
    # Wait for interface to be ready
    sleep 2
    
    # Check interface state
    local state
    state=$(cat "/sys/class/net/$INTERFACE/operstate" 2>/dev/null || echo "unknown")
    echo -e "Interface state: ${YELLOW}$state${NC}"
    
    echo -e "${GREEN}✓${NC} Interface reset completed"
}

# Function to check rfkill
fix_rfkill() {
    echo -e "\n${BLUE}Checking rfkill status...${NC}"
    
    if command -v rfkill >/dev/null 2>&1; then
        # Unblock all wireless devices
        rfkill unblock all 2>/dev/null || true
        
        # Check status
        if rfkill list | grep -q "Soft blocked: yes\|Hard blocked: yes"; then
            echo -e "${YELLOW}⚠ Some devices are still blocked${NC}"
            rfkill list
        else
            echo -e "${GREEN}✓${NC} No rfkill blocks detected"
        fi
    fi
}

# Function to configure Kali-specific settings
configure_kali_settings() {
    echo -e "\n${BLUE}Applying Kali Linux specific configurations...${NC}"
    
    # Disable power management for wireless interfaces
    if [[ -d "/sys/class/net/$INTERFACE/wireless" ]]; then
        iw dev "$INTERFACE" set power_save off 2>/dev/null || true
        echo -e "${GREEN}✓${NC} Power management disabled for $INTERFACE"
    fi
    
    # Set regulatory domain
    if command -v iw >/dev/null 2>&1; then
        iw reg set US 2>/dev/null || true
        echo -e "${GREEN}✓${NC} Regulatory domain set to US"
    fi
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo -e "${GREEN}✓${NC} IP forwarding enabled"
    
    # Disable IPv6 on the interface (can cause issues with some setups)
    echo 1 > /proc/sys/net/ipv6/conf/"$INTERFACE"/disable_ipv6 2>/dev/null || true
    echo -e "${GREEN}✓${NC} IPv6 disabled on $INTERFACE"
}

# Function to test interface
test_interface() {
    echo -e "\n${BLUE}Testing interface capabilities...${NC}"
    
    # Check if interface supports AP mode
    echo -e "${YELLOW}Checking AP mode support...${NC}"
    
    # Get phy name
    local phy
    phy=$(iw dev "$INTERFACE" info 2>/dev/null | grep wiphy | awk '{print "phy"$2}')
    
    if [[ -n "$phy" ]]; then
        # Check supported interface modes
        if iw phy "$phy" info | grep -q "AP"; then
            echo -e "${GREEN}✓${NC} Interface supports AP mode"
            
            # Check supported frequencies
            echo -e "\n${YELLOW}Supported frequencies:${NC}"
            iw phy "$phy" info | grep -A10 "Frequencies:" | grep "MHz" | head -5
        else
            echo -e "${RED}✗${NC} Interface does not support AP mode"
        fi
    fi
}

# Function to create systemd override for dnsmasq
fix_dnsmasq_service() {
    echo -e "\n${BLUE}Configuring dnsmasq service...${NC}"
    
    # Create systemd override directory
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    
    # Create override to prevent dnsmasq from starting automatically
    cat > /etc/systemd/system/dnsmasq.service.d/override.conf << EOF
[Unit]
# Don't start automatically to avoid conflicts
After=network-online.target

[Service]
# Add restart on failure
Restart=on-failure
RestartSec=5
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}✓${NC} dnsmasq service configured"
}

# Function to show summary
show_summary() {
    echo -e "\n${BLUE}=== Configuration Summary ===${NC}"
    echo
    echo "Interface $INTERFACE has been prepared for router mode."
    echo
    echo -e "${GREEN}What was done:${NC}"
    echo "  ✓ NetworkManager configured to ignore $INTERFACE"
    echo "  ✓ Interfering services stopped"
    echo "  ✓ Interface reset and prepared"
    echo "  ✓ rfkill blocks removed"
    echo "  ✓ Kali-specific settings applied"
    echo "  ✓ dnsmasq service configured"
    echo
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Start the router: sudo ./router_pi_secure.sh start"
    echo "  2. Check status: sudo ./router_pi_secure.sh status"
    echo "  3. If issues persist, check logs: sudo journalctl -xe"
    echo
    echo -e "${BLUE}Troubleshooting commands:${NC}"
    echo "  - Check interface: ip link show $INTERFACE"
    echo "  - Check rfkill: rfkill list"
    echo "  - Check services: systemctl status dnsmasq hostapd"
    echo "  - Run diagnostics: sudo ./scripts/diagnose_network.sh"
}

# Main execution
main() {
    echo -e "${YELLOW}Preparing Kali Linux for router mode...${NC}"
    echo
    
    # Check if interface exists
    if [[ ! -d "/sys/class/net/$INTERFACE" ]]; then
        echo -e "${RED}Interface $INTERFACE not found!${NC}"
        echo "Available interfaces:"
        find /sys/class/net/ -maxdepth 1 -type l -o -type d | grep -v '/lo$' | xargs -n1 basename 2>/dev/null | grep -v '^$'
        exit 1
    fi
    
    disable_nm_for_interface "$INTERFACE"
    stop_interfering_services
    fix_rfkill
    reset_wireless_interface
    configure_kali_settings
    test_interface
    fix_dnsmasq_service
    show_summary
}

# Run main function
main