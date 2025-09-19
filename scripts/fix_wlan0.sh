#!/bin/bash
#===============================================================================
# Fix wlan0 Interface Issues
# Diagnose and fix common wireless interface problems
#===============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

INTERFACE="${1:-wlan0}"

echo -e "${BLUE}=== Fixing $INTERFACE Interface Issues ===${NC}"
echo

# Function to check if running as root
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}This script must be run as root (use sudo)${NC}"
        exit 1
    fi
}

# Function to check if interface exists
check_interface_exists() {
    if [[ ! -d "/sys/class/net/$INTERFACE" ]]; then
        echo -e "${RED}Interface $INTERFACE does not exist${NC}"
        echo
        echo "Available interfaces:"
        ls /sys/class/net/ | grep -v lo | while read -r iface; do
            if [[ -d "/sys/class/net/$iface/wireless" ]]; then
                echo -e "  ${YELLOW}$iface${NC} (wireless)"
            else
                echo "  $iface"
            fi
        done
        exit 1
    fi
    echo -e "${GREEN}✓${NC} Interface $INTERFACE exists"
}

# Function to check interface state
check_interface_state() {
    local state=$(cat "/sys/class/net/$INTERFACE/operstate" 2>/dev/null || echo "unknown")
    echo -e "Interface state: ${YELLOW}$state${NC}"
    
    if [[ "$state" == "down" ]]; then
        echo -e "${YELLOW}Interface is down, attempting to bring it up...${NC}"
        
        # Try multiple methods to bring interface up
        if command -v ip >/dev/null 2>&1; then
            ip link set "$INTERFACE" up 2>/dev/null || echo -e "${RED}Failed with ip command${NC}"
        elif command -v ifconfig >/dev/null 2>&1; then
            ifconfig "$INTERFACE" up 2>/dev/null || echo -e "${RED}Failed with ifconfig${NC}"
        else
            echo 1 > "/sys/class/net/$INTERFACE/flags" 2>/dev/null || echo -e "${RED}Failed with sysfs${NC}"
        fi
        
        sleep 2
        state=$(cat "/sys/class/net/$INTERFACE/operstate" 2>/dev/null || echo "unknown")
        echo -e "New state: ${YELLOW}$state${NC}"
    fi
}

# Function to kill conflicting processes
kill_conflicting_processes() {
    echo -e "\n${BLUE}Checking for conflicting processes...${NC}"
    
    local killed=0
    for process in wpa_supplicant dhclient dhcpcd NetworkManager; do
        if pgrep -f "$process.*$INTERFACE" >/dev/null 2>&1; then
            echo -e "${YELLOW}Killing $process on $INTERFACE${NC}"
            pkill -f "$process.*$INTERFACE" 2>/dev/null || true
            killed=1
        fi
    done
    
    if [[ $killed -eq 1 ]]; then
        sleep 2
        echo -e "${GREEN}✓${NC} Conflicting processes terminated"
    else
        echo -e "${GREEN}✓${NC} No conflicting processes found"
    fi
}

# Function to reset interface
reset_interface() {
    echo -e "\n${BLUE}Resetting interface...${NC}"
    
    # Bring interface down
    if command -v ip >/dev/null 2>&1; then
        ip link set "$INTERFACE" down 2>/dev/null || true
        ip addr flush dev "$INTERFACE" 2>/dev/null || true
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig "$INTERFACE" down 2>/dev/null || true
        ifconfig "$INTERFACE" 0.0.0.0 2>/dev/null || true
    fi
    
    sleep 2
    
    # Set interface to AP mode if it's wireless
    if [[ -d "/sys/class/net/$INTERFACE/wireless" ]]; then
        if command -v iw >/dev/null 2>&1; then
            echo -e "${YELLOW}Setting interface to AP mode...${NC}"
            iw dev "$INTERFACE" set type __ap 2>/dev/null || echo -e "${RED}Failed to set AP mode${NC}"
        fi
    fi
    
    # Bring interface up
    if command -v ip >/dev/null 2>&1; then
        ip link set "$INTERFACE" up 2>/dev/null || true
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig "$INTERFACE" up 2>/dev/null || true
    fi
    
    sleep 2
    echo -e "${GREEN}✓${NC} Interface reset completed"
}

# Function to check rfkill
check_rfkill() {
    echo -e "\n${BLUE}Checking rfkill status...${NC}"
    
    if command -v rfkill >/dev/null 2>&1; then
        if rfkill list | grep -q "Soft blocked: yes\|Hard blocked: yes"; then
            echo -e "${YELLOW}Wireless is blocked by rfkill${NC}"
            rfkill unblock all
            echo -e "${GREEN}✓${NC} Unblocked all wireless devices"
        else
            echo -e "${GREEN}✓${NC} No rfkill blocks detected"
        fi
    else
        echo -e "${YELLOW}rfkill command not found, checking sysfs...${NC}"
        
        # Check sysfs for rfkill
        for rfkill in /sys/class/rfkill/*/; do
            if [[ -f "$rfkill/name" ]] && grep -q "$INTERFACE" "$rfkill/name" 2>/dev/null; then
                if [[ -f "$rfkill/soft" ]] && [[ "$(cat "$rfkill/soft")" == "1" ]]; then
                    echo 0 > "$rfkill/soft"
                    echo -e "${GREEN}✓${NC} Unblocked via sysfs"
                fi
            fi
        done
    fi
}

# Function to check and load drivers
check_drivers() {
    echo -e "\n${BLUE}Checking wireless drivers...${NC}"
    
    # Check if interface has a driver
    if [[ -L "/sys/class/net/$INTERFACE/device/driver" ]]; then
        local driver
        driver=$(basename "$(readlink "/sys/class/net/$INTERFACE/device/driver")")
        echo -e "${GREEN}✓${NC} Driver loaded: $driver"
        
        # Check module info
        if command -v modinfo >/dev/null 2>&1; then
            modinfo "$driver" 2>/dev/null | grep -E "^(filename|description):" | head -2
        fi
    else
        echo -e "${YELLOW}No driver information available${NC}"
    fi
    
    # Check for common wireless modules
    echo -e "\nLoaded wireless modules:"
    lsmod | grep -E "802|wifi|wlan|wireless|rtl|ath|mt76" | head -10 || echo "No wireless modules found"
}

# Function to test interface
test_interface() {
    echo -e "\n${BLUE}Testing interface capabilities...${NC}"
    
    # Check if interface supports AP mode
    if command -v iw >/dev/null 2>&1 && [[ -d "/sys/class/net/$INTERFACE/wireless" ]]; then
        echo -e "\nChecking AP mode support..."
        
        # Try to add a test AP interface
        local test_iface="${INTERFACE}_test"
        if iw dev "$INTERFACE" interface add "$test_iface" type __ap 2>/dev/null; then
            echo -e "${GREEN}✓${NC} Interface supports AP mode"
            iw dev "$test_iface" del 2>/dev/null
        else
            echo -e "${YELLOW}Interface may not support AP mode or is busy${NC}"
        fi
        
        # Show interface capabilities
        echo -e "\nInterface information:"
        iw dev "$INTERFACE" info 2>/dev/null || echo "Could not get interface info"
    fi
}

# Function to configure interface for router mode
configure_for_router() {
    echo -e "\n${BLUE}Configuring interface for router mode...${NC}"
    
    local ip_addr="${AP_ADDR:-10.5.5.1/24}"
    
    # Set IP address
    if command -v ip >/dev/null 2>&1; then
        ip addr add "$ip_addr" dev "$INTERFACE" 2>/dev/null || echo -e "${YELLOW}IP may already be assigned${NC}"
        echo -e "${GREEN}✓${NC} IP address configured: $ip_addr"
    elif command -v ifconfig >/dev/null 2>&1; then
        local ip="${ip_addr%/*}"
        ifconfig "$INTERFACE" "$ip" netmask 255.255.255.0 2>/dev/null || echo -e "${YELLOW}IP configuration failed${NC}"
    fi
    
    # Enable the interface
    if command -v ip >/dev/null 2>&1; then
        ip link set "$INTERFACE" up
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig "$INTERFACE" up
    fi
    
    # Show final configuration
    echo -e "\nFinal interface configuration:"
    if command -v ip >/dev/null 2>&1; then
        ip addr show "$INTERFACE"
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig "$INTERFACE"
    else
        cat "/sys/class/net/$INTERFACE/address" 2>/dev/null || echo "No address info"
    fi
}

# Function to show summary and recommendations
show_summary() {
    echo -e "\n${BLUE}=== Summary and Recommendations ===${NC}"
    
    local state=$(cat "/sys/class/net/$INTERFACE/operstate" 2>/dev/null || echo "unknown")
    
    if [[ "$state" == "up" ]] || [[ "$state" == "unknown" ]]; then
        echo -e "${GREEN}✓${NC} Interface $INTERFACE is ready for use"
        echo
        echo "To start the router, run:"
        echo -e "  ${YELLOW}sudo ./router_pi_container.sh start${NC}"
    else
        echo -e "${RED}✗${NC} Interface $INTERFACE is still down"
        echo
        echo "Troubleshooting steps:"
        echo "1. Check dmesg for errors: dmesg | grep -i $INTERFACE"
        echo "2. Try a different interface if available"
        echo "3. Check if the wireless adapter is properly connected"
        echo "4. Try rebooting the system"
    fi
    
    echo
    echo "Additional debugging commands:"
    echo "  - View kernel messages: dmesg | tail -50"
    echo "  - Check USB devices: lsusb"
    echo "  - List network interfaces: ls /sys/class/net/"
    echo "  - Check wireless info: iw list (if available)"
}

# Main execution
main() {
    check_root
    
    echo -e "${YELLOW}Attempting to fix $INTERFACE...${NC}"
    echo
    
    check_interface_exists
    check_interface_state
    kill_conflicting_processes
    check_rfkill
    reset_interface
    check_drivers
    test_interface
    configure_for_router
    show_summary
}

# Run main function
main