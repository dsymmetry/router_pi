#!/bin/bash
#===============================================================================
# 🔐 RPi5 Secure Travel Router - Container-Friendly Version
# Adapted for environments without systemd
#===============================================================================

set -euo pipefail

# Version and metadata
VERSION="2.1.0-container"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# === NETWORK CONFIGURATION ===
LAN_IFACE="${LAN_IFACE:-wlan0}"                  # AP interface
WAN_IFACE="${WAN_IFACE:-eth0}"                   # WAN interface
AP_ADDR="${AP_ADDR:-10.5.5.1/24}"               # AP subnet
DHCP_RANGE="${DHCP_RANGE:-10.5.5.10,10.5.5.50,12h}"
USE_5GHZ="${USE_5GHZ:-false}"                    # Use 2.4GHz for better compatibility
SSID_PREFIX="${SSID_PREFIX:-SecureTravel}"       # WiFi network prefix
COUNTRY_CODE="${COUNTRY_CODE:-US}"               # Regulatory domain

# === PATHS ===
HOSTAPD_CONF="/tmp/hostapd.conf"
DNSMASQ_CONF="/tmp/dnsmasq.conf"
STATE_DIR="/tmp/routerpi"
LOG_DIR="/tmp/routerpi/logs"
WIFI_PASSWORD_FILE="$STATE_DIR/wifi_password"

# Create required directories
mkdir -p "$STATE_DIR" "$LOG_DIR" 2>/dev/null || true

# === UTILITY FUNCTIONS ===
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_DIR/router.log"
}

error() {
    echo "ERROR: $*" >&2
    exit 1
}

check_root() {
    [[ "$EUID" -eq 0 ]] || error "This script must be run as root (use sudo)"
}

generate_strong_password() {
    # Fallback password generation without openssl
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
    else
        # Simple fallback
        echo "SecurePass$(date +%s | sha256sum | base64 | head -c 15)"
    fi
}

# Check if running in container
is_container() {
    if [[ -f /.dockerenv ]] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        return 0
    fi
    return 1
}

# === NETWORK TOOLS FUNCTIONS ===
# Fallback functions for missing network tools

check_interface_exists() {
    local iface="$1"
    [[ -d "/sys/class/net/$iface" ]]
}

bring_interface_down() {
    local iface="$1"
    if command -v ip >/dev/null 2>&1; then
        ip link set "$iface" down 2>/dev/null || true
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig "$iface" down 2>/dev/null || true
    else
        echo 0 > "/sys/class/net/$iface/flags" 2>/dev/null || true
    fi
}

bring_interface_up() {
    local iface="$1"
    if command -v ip >/dev/null 2>&1; then
        ip link set "$iface" up 2>/dev/null || true
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig "$iface" up 2>/dev/null || true
    else
        echo 1 > "/sys/class/net/$iface/flags" 2>/dev/null || true
    fi
}

set_interface_ip() {
    local iface="$1"
    local ip_addr="$2"
    
    if command -v ip >/dev/null 2>&1; then
        ip addr flush dev "$iface" 2>/dev/null || true
        ip addr add "$ip_addr" dev "$iface" 2>/dev/null || true
    elif command -v ifconfig >/dev/null 2>&1; then
        local ip="${ip_addr%/*}"
        local mask="255.255.255.0"  # Assuming /24
        ifconfig "$iface" "$ip" netmask "$mask" 2>/dev/null || true
    else
        error "No network configuration tool available"
    fi
}

# === DNSMASQ CONFIGURATION ===
generate_dnsmasq_config() {
    log "Generating dnsmasq configuration..."
    
    local ip_base="${AP_ADDR%/*}"
    local broadcast_addr="${ip_base%.*}.255"
    
    cat > "$DNSMASQ_CONF" << EOF
# Container-friendly dnsmasq configuration
interface=$LAN_IFACE
bind-interfaces
except-interface=lo
listen-address=$ip_base

# DHCP configuration
dhcp-range=$DHCP_RANGE
dhcp-option=option:router,$ip_base
dhcp-option=option:dns-server,$ip_base
dhcp-option=option:netmask,255.255.255.0
dhcp-option=option:broadcast,$broadcast_addr

# DNS configuration
server=1.1.1.1
server=9.9.9.9
no-resolv
cache-size=1000

# Security
bogus-priv
domain-needed
stop-dns-rebind
rebind-localhost-ok

# Logging
log-queries
log-dhcp
log-facility=$LOG_DIR/dnsmasq.log

# Don't run as daemon in container
keep-in-foreground
EOF

    log "✓ dnsmasq configuration generated"
}

# === HOSTAPD CONFIGURATION ===
generate_hostapd_config() {
    local password="$1"
    
    log "Generating hostapd configuration..."
    
    # Generate unique SSID
    local mac_suffix="$(date +%s | tail -c 5)"
    local ssid="${SSID_PREFIX}_${mac_suffix}"
    
    # Determine channel and hardware mode
    local channel hw_mode
    if [[ "$USE_5GHZ" == "true" ]]; then
        channel=36
        hw_mode="a"
    else
        channel=6
        hw_mode="g"
    fi
    
    cat > "$HOSTAPD_CONF" << EOF
# Container-friendly hostapd configuration
interface=$LAN_IFACE
driver=nl80211

# Basic settings
ssid=$ssid
hw_mode=$hw_mode
channel=$channel
country_code=$COUNTRY_CODE

# Security
auth_algs=1
wpa=2
wpa_passphrase=$password
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP

# 802.11n settings
ieee80211n=1
wmm_enabled=1
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]

# Security features
ap_isolate=0
max_num_sta=10

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=1
EOF

    log "✓ Hostapd configuration generated for SSID: $ssid"
}

# === FIREWALL CONFIGURATION ===
setup_firewall() {
    log "Setting up firewall rules..."
    
    if ! command -v iptables >/dev/null 2>&1; then
        log "WARNING: iptables not available, skipping firewall setup"
        return
    fi
    
    # Flush existing rules
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    
    # Enable NAT
    iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE
    
    # Allow forwarding
    iptables -A FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT
    iptables -A FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow DNS and DHCP
    iptables -A INPUT -i "$LAN_IFACE" -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$LAN_IFACE" -p tcp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$LAN_IFACE" -p udp --dport 67 -j ACCEPT
    
    log "✓ Firewall rules configured"
}

# === MAIN FUNCTIONS ===
start_router() {
    check_root
    log "🚀 Starting secure router (container mode)..."
    
    # Check if we're in a container
    if is_container; then
        log "Running in container environment"
    fi
    
    # Check interfaces
    if ! check_interface_exists "$LAN_IFACE"; then
        error "LAN interface $LAN_IFACE not found"
    fi
    
    if ! check_interface_exists "$WAN_IFACE"; then
        log "WARNING: WAN interface $WAN_IFACE not found, continuing anyway"
    fi
    
    # Generate WiFi password if not exists
    if [[ ! -f "$WIFI_PASSWORD_FILE" ]]; then
        generate_strong_password > "$WIFI_PASSWORD_FILE"
        chmod 600 "$WIFI_PASSWORD_FILE"
        log "✓ Generated new WiFi password"
    fi
    local wifi_password
    wifi_password=$(cat "$WIFI_PASSWORD_FILE")
    
    # Configure LAN interface
    log "Configuring LAN interface: $LAN_IFACE"
    
    # Kill any processes using the interface
    pkill -f "wpa_supplicant.*$LAN_IFACE" 2>/dev/null || true
    pkill -f "dhclient.*$LAN_IFACE" 2>/dev/null || true
    pkill -f "dhcpcd.*$LAN_IFACE" 2>/dev/null || true
    sleep 1
    
    # Configure interface
    bring_interface_down "$LAN_IFACE"
    sleep 2
    
    # Set IP address
    set_interface_ip "$LAN_IFACE" "$AP_ADDR"
    
    # Bring interface up
    bring_interface_up "$LAN_IFACE"
    sleep 2
    
    # Verify interface is up
    if [[ -f "/sys/class/net/$LAN_IFACE/operstate" ]]; then
        local state=$(cat "/sys/class/net/$LAN_IFACE/operstate")
        log "Interface $LAN_IFACE state: $state"
    fi
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Setup firewall
    setup_firewall
    
    # Generate configurations
    generate_dnsmasq_config
    generate_hostapd_config "$wifi_password"
    
    # Start services
    log "Starting network services..."
    
    # Kill any existing instances
    pkill dnsmasq 2>/dev/null || true
    pkill hostapd 2>/dev/null || true
    sleep 1
    
    # Start dnsmasq
    log "Starting dnsmasq..."
    if command -v dnsmasq >/dev/null 2>&1; then
        # Test configuration
        if dnsmasq --test -C "$DNSMASQ_CONF" 2>&1 | grep -q "OK"; then
            # Start in background
            dnsmasq -C "$DNSMASQ_CONF" -d > "$LOG_DIR/dnsmasq.out" 2>&1 &
            echo $! > "$STATE_DIR/dnsmasq.pid"
            log "✓ dnsmasq started (PID: $(cat "$STATE_DIR/dnsmasq.pid"))"
        else
            log "ERROR: dnsmasq configuration test failed"
            dnsmasq --test -C "$DNSMASQ_CONF"
        fi
    else
        log "ERROR: dnsmasq not found"
    fi
    
    # Wait a bit for dnsmasq to start
    sleep 2
    
    # Start hostapd
    log "Starting hostapd..."
    if command -v hostapd >/dev/null 2>&1; then
        # Start in background
        hostapd "$HOSTAPD_CONF" > "$LOG_DIR/hostapd.out" 2>&1 &
        echo $! > "$STATE_DIR/hostapd.pid"
        log "✓ hostapd started (PID: $(cat "$STATE_DIR/hostapd.pid"))"
    else
        log "ERROR: hostapd not found"
    fi
    
    # Save state
    echo "started" > "$STATE_DIR/router_state"
    echo "$WAN_IFACE" > "$STATE_DIR/wan_interface"
    echo "$LAN_IFACE" > "$STATE_DIR/lan_interface"
    
    log "✅ Secure router started successfully!"
    log "📶 SSID: $(grep '^ssid=' "$HOSTAPD_CONF" | cut -d= -f2)"
    log "🔑 Password: $wifi_password"
    log "🌐 Router IP: ${AP_ADDR%/*}"
    
    # Show process status
    echo
    log "Service status:"
    if [[ -f "$STATE_DIR/dnsmasq.pid" ]] && kill -0 "$(cat "$STATE_DIR/dnsmasq.pid")" 2>/dev/null; then
        log "  ✅ dnsmasq is running"
    else
        log "  ❌ dnsmasq is not running"
    fi
    
    if [[ -f "$STATE_DIR/hostapd.pid" ]] && kill -0 "$(cat "$STATE_DIR/hostapd.pid")" 2>/dev/null; then
        log "  ✅ hostapd is running"
    else
        log "  ❌ hostapd is not running"
    fi
}

stop_router() {
    check_root
    log "🛑 Stopping secure router..."
    
    # Stop services
    if [[ -f "$STATE_DIR/hostapd.pid" ]]; then
        kill "$(cat "$STATE_DIR/hostapd.pid")" 2>/dev/null || true
        rm -f "$STATE_DIR/hostapd.pid"
    fi
    
    if [[ -f "$STATE_DIR/dnsmasq.pid" ]]; then
        kill "$(cat "$STATE_DIR/dnsmasq.pid")" 2>/dev/null || true
        rm -f "$STATE_DIR/dnsmasq.pid"
    fi
    
    # Kill any remaining processes
    pkill hostapd 2>/dev/null || true
    pkill dnsmasq 2>/dev/null || true
    
    # Clear firewall rules if iptables is available
    if command -v iptables >/dev/null 2>&1; then
        iptables -F 2>/dev/null || true
        iptables -t nat -F 2>/dev/null || true
    fi
    
    # Reset interface
    if [[ -f "$STATE_DIR/lan_interface" ]]; then
        local lan_iface
        lan_iface=$(cat "$STATE_DIR/lan_interface")
        bring_interface_down "$lan_iface" 2>/dev/null || true
    fi
    
    # Clear state
    rm -f "$STATE_DIR/router_state"
    rm -f "$STATE_DIR/wan_interface"
    rm -f "$STATE_DIR/lan_interface"
    
    log "✅ Secure router stopped"
}

status_router() {
    echo "=== 🔐 Secure Router Status (Container Mode) ==="
    echo
    
    if [[ -f "$STATE_DIR/router_state" ]]; then
        echo "🟢 Status: RUNNING"
        echo "📅 Started: $(stat -c %y "$STATE_DIR/router_state" 2>/dev/null | cut -d. -f1)"
    else
        echo "🔴 Status: STOPPED"
        return 0
    fi
    
    echo
    echo "🌐 Network Interfaces:"
    if [[ -f "$STATE_DIR/wan_interface" ]]; then
        wan_iface=$(cat "$STATE_DIR/wan_interface")
        lan_iface=$(cat "$STATE_DIR/lan_interface")
        echo "  WAN: $wan_iface"
        echo "  LAN: $lan_iface"
    fi
    
    echo
    echo "📶 WiFi Configuration:"
    if [[ -f "$HOSTAPD_CONF" ]]; then
        echo "  SSID: $(grep '^ssid=' "$HOSTAPD_CONF" | cut -d= -f2)"
        echo "  Channel: $(grep '^channel=' "$HOSTAPD_CONF" | cut -d= -f2)"
        if [[ -f "$WIFI_PASSWORD_FILE" ]]; then
            echo "  Password: $(cat "$WIFI_PASSWORD_FILE")"
        fi
    fi
    
    echo
    echo "🔧 Service Status:"
    if [[ -f "$STATE_DIR/dnsmasq.pid" ]] && kill -0 "$(cat "$STATE_DIR/dnsmasq.pid")" 2>/dev/null; then
        echo "  ✅ dnsmasq is running (PID: $(cat "$STATE_DIR/dnsmasq.pid"))"
    else
        echo "  ❌ dnsmasq is not running"
    fi
    
    if [[ -f "$STATE_DIR/hostapd.pid" ]] && kill -0 "$(cat "$STATE_DIR/hostapd.pid")" 2>/dev/null; then
        echo "  ✅ hostapd is running (PID: $(cat "$STATE_DIR/hostapd.pid"))"
    else
        echo "  ❌ hostapd is not running"
    fi
    
    echo
}

show_logs() {
    echo "=== 📋 Router Logs ==="
    echo
    
    if [[ -f "$LOG_DIR/dnsmasq.out" ]]; then
        echo "--- dnsmasq logs ---"
        tail -20 "$LOG_DIR/dnsmasq.out"
        echo
    fi
    
    if [[ -f "$LOG_DIR/hostapd.out" ]]; then
        echo "--- hostapd logs ---"
        tail -20 "$LOG_DIR/hostapd.out"
        echo
    fi
    
    if [[ -f "$LOG_DIR/router.log" ]]; then
        echo "--- router logs ---"
        tail -20 "$LOG_DIR/router.log"
    fi
}

show_help() {
    cat << EOF
🔐 Secure Travel Router v$VERSION

USAGE:
    $SCRIPT_NAME {start|stop|status|logs|help}

COMMANDS:
    start      Start secure router mode
    stop       Stop router mode
    status     Show current router status
    logs       Show recent logs
    help       Show this help message

ENVIRONMENT VARIABLES:
    WAN_IFACE    WAN interface (default: eth0)
    LAN_IFACE    LAN/AP interface (default: wlan0)
    AP_ADDR      Router IP and subnet (default: 10.5.5.1/24)
    USE_5GHZ     Use 5GHz band (default: false)

This version is optimized for container environments without systemd.

EOF
}

# === MAIN EXECUTION ===
case "${1:-help}" in
    start)
        start_router
        ;;
    stop)
        stop_router
        ;;
    status)
        status_router
        ;;
    logs)
        show_logs
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Error: Unknown command '$1'"
        show_help
        exit 1
        ;;
esac