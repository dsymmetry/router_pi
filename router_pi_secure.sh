#!/bin/bash
#===============================================================================
# 🔐 RPi5 Secure Travel Router - Complete Security Implementation
# Optimized for MT7612U (Panda Wireless) on Kali Linux
#===============================================================================

set -euo pipefail

# Version and metadata
VERSION="2.0.0"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# === SECURITY CONFIGURATION ===
SECURITY_MODE="${SECURITY_MODE:-high}"           # high, medium, low
ENABLE_IDS="${ENABLE_IDS:-true}"                 # Enable Suricata IDS
ENABLE_IPS="${ENABLE_IPS:-true}"                 # Enable auto-blocking
ENABLE_AUDIT_LOG="${ENABLE_AUDIT_LOG:-true}"     # Security event logging
BLOCK_TIME="${BLOCK_TIME:-3600}"                 # Auto-unblock time (seconds)
MAX_CONN_PER_IP="${MAX_CONN_PER_IP:-20}"        # Connection limit per IP
SCAN_THRESHOLD="${SCAN_THRESHOLD:-10}"           # Port scan detection threshold

# === NETWORK CONFIGURATION ===
LAN_IFACE="${LAN_IFACE:-wlan0}"                  # AP interface (MT7612U)
WAN_IFACE="${WAN_IFACE:-$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')}"
AP_ADDR="${AP_ADDR:-192.168.8.1/24}"             # AP subnet
DHCP_RANGE="${DHCP_RANGE:-192.168.8.10,192.168.8.50,12h}"
USE_5GHZ="${USE_5GHZ:-true}"                     # Use 5GHz by default
SSID_PREFIX="${SSID_PREFIX:-SecureTravel}"       # WiFi network prefix
COUNTRY_CODE="${COUNTRY_CODE:-US}"               # Regulatory domain
HIDDEN_SSID="${HIDDEN_SSID:-false}"              # Hide SSID broadcast

# === SECURITY PATHS ===
HOSTAPD_CONF="${HOSTAPD_CONF:-/etc/hostapd/hostapd.conf}"
DNSMASQ_DROPIN="/etc/dnsmasq.d/router-secure.conf"
SURICATA_CONF="/etc/suricata/suricata.yaml"
STATE_DIR="/run/routerpi"
LOG_DIR="/var/log/routerpi"
CONFIG_DIR="/etc/routerpi"
BLOCKED_IPS_FILE="$STATE_DIR/blocked_ips"
WIFI_PASSWORD_FILE="$STATE_DIR/wifi_password"
SECURITY_LOG="$LOG_DIR/security.log"
TRAFFIC_LOG="$LOG_DIR/traffic.log"

# Create required directories
mkdir -p "$STATE_DIR" "$LOG_DIR" "$CONFIG_DIR" 2>/dev/null || true

# === UTILITY FUNCTIONS ===
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_DIR/router.log"
}

log_security() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SECURITY: $*" | tee -a "$SECURITY_LOG"
}

error() {
    echo "ERROR: $*" >&2
    exit 1
}

require() {
    command -v "$1" >/dev/null 2>&1 || error "Missing required command: $1"
}

check_root() {
    [[ $EUID -eq 0 ]] || error "This script must be run as root (use sudo)"
}

generate_strong_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

get_interface_mac() {
    local iface="$1"
    cat "/sys/class/net/$iface/address" 2>/dev/null || echo "unknown"
}

# === MT7612U SPECIFIC FUNCTIONS ===
detect_mt7612u() {
    log "Detecting MT7612U adapter..."
    
    # Check USB devices
    if lsusb | grep -q "0e8d:7612"; then
        log "✓ MT7612U detected via USB"
        return 0
    fi
    
    # Check network interfaces
    for iface in /sys/class/net/*/; do
        if [[ -f "$iface/device/modalias" ]]; then
            if grep -q "mt76" "$iface/device/modalias" 2>/dev/null; then
                log "✓ MT76-based interface detected: $(basename "$iface")"
                return 0
            fi
        fi
    done
    
    log "⚠ MT7612U not detected - continuing anyway"
    return 1
}

reset_mt7612u() {
    log "Resetting MT7612U adapter..."
    
    # Unload and reload driver
    modprobe -r mt76x2u 2>/dev/null || true
    sleep 2
    modprobe mt76x2u 2>/dev/null || true
    sleep 3
    
    log "✓ MT7612U reset completed"
}

configure_mt7612u() {
    local iface="$1"
    
    log "Configuring MT7612U interface: $iface"
    
    # Set interface down
    ip link set "$iface" down 2>/dev/null || true
    
    # Configure for AP mode
    iw dev "$iface" set type __ap 2>/dev/null || true
    
    # Set regulatory domain
    iw reg set "$COUNTRY_CODE" 2>/dev/null || true
    
    # Power management off for stability
    iw dev "$iface" set power_save off 2>/dev/null || true
    
    log "✓ MT7612U interface configured"
}

# === SECURITY FUNCTIONS ===
setup_firewall() {
    log "Setting up advanced firewall rules..."
    
    # Use external script if available
    if [[ -f "$SCRIPT_DIR/configs/iptables_rules.sh" ]]; then
        source "$SCRIPT_DIR/configs/iptables_rules.sh"
        return 0
    fi
    
    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # === INPUT CHAIN ===
    # Loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # ICMP (rate limited)
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    
    # SSH (rate limited) - only from LAN
    iptables -A INPUT -i "$LAN_IFACE" -p tcp --dport 22 -m state --state NEW -m recent --set --name ssh
    iptables -A INPUT -i "$LAN_IFACE" -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name ssh -j DROP
    iptables -A INPUT -i "$LAN_IFACE" -p tcp --dport 22 -j ACCEPT
    
    # DNS for clients
    iptables -A INPUT -i "$LAN_IFACE" -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$LAN_IFACE" -p tcp --dport 53 -j ACCEPT
    
    # DHCP
    iptables -A INPUT -i "$LAN_IFACE" -p udp --dport 67 -j ACCEPT
    
    # === FORWARD CHAIN ===
    # Connection tracking
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Rate limiting per IP
    iptables -A FORWARD -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name conn_rate_limit -j DROP
    
    # Connection limit per IP
    iptables -A FORWARD -p tcp --syn -m connlimit --connlimit-above "$MAX_CONN_PER_IP" --connlimit-mask 32 -j REJECT --reject-with tcp-reset
    
    # Allow LAN to WAN
    iptables -A FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT
    
    # === NAT RULES ===
    iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE
    
    # === LOGGING ===
    # Log dropped packets (rate limited)
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "ROUTER-DROP-INPUT: " --log-level 4
    iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "ROUTER-DROP-FORWARD: " --log-level 4
    
    log "✓ Advanced firewall rules configured"
}

generate_hostapd_config() {
    local password="$1"
    local channel="$2"
    local hw_mode="$3"
    
    log "Generating hostapd configuration..."
    
    # Use external config if available
    if [[ -f "$SCRIPT_DIR/configs/hostapd_mt7612u.conf" ]]; then
        cp "$SCRIPT_DIR/configs/hostapd_mt7612u.conf" "$HOSTAPD_CONF"
        # Update dynamic values
        sed -i "s/INTERFACE_PLACEHOLDER/$LAN_IFACE/g" "$HOSTAPD_CONF"
        sed -i "s/PASSWORD_PLACEHOLDER/$password/g" "$HOSTAPD_CONF"
        sed -i "s/CHANNEL_PLACEHOLDER/$channel/g" "$HOSTAPD_CONF"
        sed -i "s/HW_MODE_PLACEHOLDER/$hw_mode/g" "$HOSTAPD_CONF"
        return 0
    fi
    
    # Generate unique SSID
    local mac_suffix
    mac_suffix=$(get_interface_mac "$LAN_IFACE" | tr -d ':' | tail -c 5)
    local ssid="${SSID_PREFIX}_${mac_suffix}"
    
    cat > "$HOSTAPD_CONF" << EOF
# MT7612U Optimized Configuration
interface=$LAN_IFACE
driver=nl80211

# Basic AP settings
ssid=$ssid
hw_mode=$hw_mode
channel=$channel
country_code=$COUNTRY_CODE

# Security settings
auth_algs=1
ignore_broadcast_ssid=$([ "$HIDDEN_SSID" = "true" ] && echo "1" || echo "0")

# WPA2/WPA3 Configuration
wpa=2
wpa_passphrase=$password
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP

# 802.11n/ac settings
ieee80211n=1
ieee80211ac=$([ "$hw_mode" = "a" ] && echo "1" || echo "0")
wmm_enabled=1

# MT7612U specific optimizations
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1]
vht_capab=[MAX-MPDU-11454][RXLDPC][SHORT-GI-80][TX-STBC-2BY1][RX-STBC-1]

# Security enhancements
ap_isolate=1
disassoc_low_ack=1
skip_inactivity_poll=0
max_num_sta=10

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
EOF

    log "✓ Hostapd configuration generated for SSID: $ssid"
}

setup_dns_security() {
    log "Setting up secure DNS configuration..."
    
    # Use external config if available
    if [[ -f "$SCRIPT_DIR/configs/dnsmasq_secure.conf" ]]; then
        cp "$SCRIPT_DIR/configs/dnsmasq_secure.conf" "$DNSMASQ_DROPIN"
        # Update dynamic values
        sed -i "s/INTERFACE_PLACEHOLDER/$LAN_IFACE/g" "$DNSMASQ_DROPIN"
        sed -i "s/LISTEN_ADDRESS_PLACEHOLDER/${AP_ADDR%/*}/g" "$DNSMASQ_DROPIN"
        sed -i "s/DHCP_RANGE_PLACEHOLDER/$DHCP_RANGE/g" "$DNSMASQ_DROPIN"
        sed -i "s/ROUTER_IP_PLACEHOLDER/${AP_ADDR%/*}/g" "$DNSMASQ_DROPIN"
        return 0
    fi
    
    # Generate basic secure config
    cat > "$DNSMASQ_DROPIN" << EOF
# Interface configuration
interface=$LAN_IFACE
bind-interfaces
listen-address=${AP_ADDR%/*}

# DHCP configuration
dhcp-range=$DHCP_RANGE
dhcp-option=option:router,${AP_ADDR%/*}
dhcp-option=option:dns-server,${AP_ADDR%/*}

# DNS Security
server=1.1.1.1
server=9.9.9.9
bogus-priv
domain-needed
no-resolv
cache-size=1000

# DNS rebinding protection
stop-dns-rebind
rebind-localhost-ok

# Logging
log-queries
log-dhcp
EOF

    log "✓ Secure DNS configuration applied"
}

# === MAIN FUNCTIONS ===
start_router() {
    check_root
    log "🚀 Starting secure router mode..."
    
    # Pre-flight checks
    require iptables
    require ip
    require hostapd
    require dnsmasq
    require openssl
    
    # Detect and configure MT7612U
    detect_mt7612u
    configure_mt7612u "$LAN_IFACE"
    
    # Generate WiFi password if not exists
    if [[ ! -f "$WIFI_PASSWORD_FILE" ]]; then
        generate_strong_password > "$WIFI_PASSWORD_FILE"
        chmod 600 "$WIFI_PASSWORD_FILE"
        log "✓ Generated new WiFi password"
    fi
    local wifi_password
    wifi_password=$(cat "$WIFI_PASSWORD_FILE")
    
    # Determine channel and hardware mode
    local channel hw_mode
    if [[ "$USE_5GHZ" == "true" ]]; then
        channel=36
        hw_mode="a"
        log "Using 5GHz band (802.11ac)"
    else
        channel=6
        hw_mode="g"
        log "Using 2.4GHz band (802.11n)"
    fi
    
    # Configure network interface
    log "Configuring network interface: $LAN_IFACE"
    ip link set "$LAN_IFACE" down 2>/dev/null || true
    ip addr flush dev "$LAN_IFACE" 2>/dev/null || true
    ip addr add "$AP_ADDR" dev "$LAN_IFACE"
    ip link set "$LAN_IFACE" up
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Setup firewall
    setup_firewall
    
    # Setup DNS security
    setup_dns_security
    
    # Generate hostapd config
    generate_hostapd_config "$wifi_password" "$channel" "$hw_mode"
    
    # Start services
    log "Starting network services..."
    systemctl restart dnsmasq
    systemctl restart hostapd
    
    # Run additional scripts if available
    for script in "$SCRIPT_DIR/scripts/mt7612u_monitor.sh" "$SCRIPT_DIR/scripts/security_audit.sh"; do
        if [[ -x "$script" ]]; then
            "$script" start &
        fi
    done
    
    # Save current state
    echo "started" > "$STATE_DIR/router_state"
    echo "$WAN_IFACE" > "$STATE_DIR/wan_interface"
    echo "$LAN_IFACE" > "$STATE_DIR/lan_interface"
    
    log "✅ Secure router started successfully!"
    log "📶 SSID: $(grep '^ssid=' "$HOSTAPD_CONF" | cut -d= -f2)"
    log "🔑 Password: $wifi_password"
    log "🌐 Router IP: ${AP_ADDR%/*}"
    log "🔒 Security Level: $SECURITY_MODE"
}

stop_router() {
    check_root
    log "🛑 Stopping secure router..."
    
    # Stop services
    systemctl stop hostapd 2>/dev/null || true
    pkill hostapd 2>/dev/null || true
    
    # Stop additional scripts
    for script in mt7612u_monitor.sh security_audit.sh; do
        pkill -f "$script" 2>/dev/null || true
    done
    
    # Remove dnsmasq config and restart
    rm -f "$DNSMASQ_DROPIN"
    systemctl restart dnsmasq 2>/dev/null || true
    
    # Flush firewall rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Reset interface
    if [[ -f "$STATE_DIR/lan_interface" ]]; then
        local lan_iface
        lan_iface=$(cat "$STATE_DIR/lan_interface")
        ip link set "$lan_iface" down 2>/dev/null || true
        iw dev "$lan_iface" set type managed 2>/dev/null || true
    fi
    
    # Clear state
    rm -f "$STATE_DIR/router_state"
    rm -f "$STATE_DIR/wan_interface"
    rm -f "$STATE_DIR/lan_interface"
    
    log "✅ Secure router stopped"
}

status_router() {
    echo "=== 🔐 RPi5 Secure Router Status ==="
    echo
    
    # Basic status
    if [[ -f "$STATE_DIR/router_state" ]]; then
        echo "🟢 Status: RUNNING"
        echo "📅 Started: $(stat -c %y "$STATE_DIR/router_state" 2>/dev/null | cut -d. -f1)"
    else
        echo "🔴 Status: STOPPED"
        return 0
    fi
    
    # Network interfaces
    echo
    echo "🌐 Network Interfaces:"
    if [[ -f "$STATE_DIR/wan_interface" ]]; then
        local wan_iface lan_iface
        wan_iface=$(cat "$STATE_DIR/wan_interface" 2>/dev/null || echo "unknown")
        lan_iface=$(cat "$STATE_DIR/lan_interface" 2>/dev/null || echo "unknown")
        
        echo "  WAN: $wan_iface ($(ip -4 addr show "$wan_iface" 2>/dev/null | grep inet | awk '{print $2}' | head -1 || echo 'no IP'))"
        echo "  LAN: $lan_iface ($(ip -4 addr show "$lan_iface" 2>/dev/null | grep inet | awk '{print $2}' | head -1 || echo 'no IP'))"
    fi
    
    # WiFi information
    echo
    echo "📶 WiFi Configuration:"
    if [[ -f "$HOSTAPD_CONF" ]]; then
        local ssid channel
        ssid=$(grep '^ssid=' "$HOSTAPD_CONF" 2>/dev/null | cut -d= -f2 || echo "unknown")
        channel=$(grep '^channel=' "$HOSTAPD_CONF" 2>/dev/null | cut -d= -f2 || echo "unknown")
        echo "  SSID: $ssid"
        echo "  Channel: $channel"
        echo "  Security: WPA2/WPA3"
        
        if [[ -f "$WIFI_PASSWORD_FILE" ]]; then
            echo "  Password: $(cat "$WIFI_PASSWORD_FILE")"
        fi
    fi
    
    # Connected clients
    echo
    echo "👥 Connected Clients:"
    if command -v iw >/dev/null 2>&1 && [[ -f "$STATE_DIR/lan_interface" ]]; then
        local lan_iface client_count
        lan_iface=$(cat "$STATE_DIR/lan_interface")
        client_count=$(iw dev "$lan_iface" station dump 2>/dev/null | grep -c "Station" || echo "0")
        echo "  Active connections: $client_count"
    fi
    
    # Security status
    echo
    echo "🔒 Security Status:"
    echo "  Firewall: $(iptables -L INPUT | grep -q "DROP" && echo "ACTIVE" || echo "INACTIVE")"
    echo "  DNS Security: $(systemctl is-active dnsmasq 2>/dev/null || echo "inactive")"
    
    echo
}

monitor_router() {
    check_root
    echo "=== 📊 Real-time Router Monitoring ==="
    echo "Press Ctrl+C to stop"
    echo
    
    # Use external monitoring script if available
    if [[ -x "$SCRIPT_DIR/scripts/network_diag.sh" ]]; then
        "$SCRIPT_DIR/scripts/network_diag.sh" monitor
        return 0
    fi
    
    # Basic monitoring
    while true; do
        clear
        echo "=== Router Monitor - $(date) ==="
        echo
        
        # Active connections
        echo "🔗 Active Connections:"
        ss -tuln | grep -E ":(53|67|80|443|22)" | head -5
        
        # Interface status
        echo
        echo "🌐 Interface Status:"
        for iface in "$WAN_IFACE" "$LAN_IFACE"; do
            if [[ -d "/sys/class/net/$iface" ]]; then
                local status
                status=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
                echo "  $iface: $status"
            fi
        done
        
        sleep 5
    done
}

audit_security() {
    check_root
    echo "=== 🔍 Security Audit Report ==="
    echo
    
    # Use external audit script if available
    if [[ -x "$SCRIPT_DIR/scripts/security_audit.sh" ]]; then
        "$SCRIPT_DIR/scripts/security_audit.sh" full
        return 0
    fi
    
    local issues=0
    
    # Check firewall
    echo "🛡️ Firewall Analysis:"
    if iptables -L INPUT | grep -q "DROP"; then
        echo "  ✅ Firewall is active with DROP policy"
    else
        echo "  ❌ Firewall not properly configured"
        ((issues++))
    fi
    
    # Check services
    echo
    echo "🔧 Service Security:"
    for service in hostapd dnsmasq; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            echo "  ✅ $service is running"
        else
            echo "  ⚠️ $service is not running"
            ((issues++))
        fi
    done
    
    # Summary
    echo
    echo "📊 Audit Summary:"
    if [[ $issues -eq 0 ]]; then
        echo "  🎉 No security issues found!"
    else
        echo "  ⚠️ Found $issues potential security issues"
    fi
}

reset_adapter() {
    check_root
    log "🔄 Resetting MT7612U adapter..."
    
    # Stop services first
    systemctl stop hostapd 2>/dev/null || true
    
    # Reset the adapter
    reset_mt7612u
    
    # Wait for interface to come back
    sleep 5
    
    # Restart if router was running
    if [[ -f "$STATE_DIR/router_state" ]]; then
        log "Restarting router after adapter reset..."
        start_router
    fi
    
    log "✅ Adapter reset completed"
}

show_help() {
    cat << EOF
🔐 RPi5 Secure Travel Router v$VERSION

USAGE:
    $SCRIPT_NAME {start|stop|status|monitor|audit|reset|help}

COMMANDS:
    start      Start secure router mode
    stop       Stop router mode and restore normal operation
    status     Show current router status and configuration
    monitor    Real-time monitoring dashboard
    audit      Run security audit and show recommendations
    reset      Reset MT7612U adapter (useful for troubleshooting)
    help       Show this help message

ENVIRONMENT VARIABLES:
    WAN_IFACE      WAN interface (auto-detected by default)
    LAN_IFACE      LAN/AP interface (default: wlan0)
    AP_ADDR        Router IP and subnet (default: 192.168.8.1/24)
    USE_5GHZ       Use 5GHz band (default: true)
    SECURITY_MODE  Security level: high|medium|low (default: high)

EXAMPLES:
    # Start with 2.4GHz
    USE_5GHZ=false sudo $SCRIPT_NAME start
    
    # Use custom IP range
    AP_ADDR="10.0.0.1/24" sudo $SCRIPT_NAME start

SECURITY FEATURES:
    ✅ Advanced stateful firewall with DDoS protection
    ✅ WPA2/WPA3 encryption with strong password generation
    ✅ DNS security with malware domain blocking
    ✅ Client isolation and AP security hardening
    ✅ System hardening and comprehensive logging
    ✅ MT7612U optimization for Panda adapters

For more information, visit: https://github.com/YOUR_USERNAME/router_pi
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
    monitor)
        monitor_router
        ;;
    audit)
        audit_security
        ;;
    reset)
        reset_adapter
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Error: Unknown command '$1'"
        echo "Use '$SCRIPT_NAME help' for usage information"
        exit 1
        ;;
esac
