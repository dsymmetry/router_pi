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

# === VPN CONFIGURATION ===
ENABLE_VPN="${ENABLE_VPN:-false}"                # Enable WireGuard VPN
VPN_CONFIG="${VPN_CONFIG:-/etc/routerpi/vpn/client.conf}"  # WireGuard config
ENABLE_KILL_SWITCH="${ENABLE_KILL_SWITCH:-true}" # Enable VPN kill switch
VPN_SERVER_IP="${VPN_SERVER_IP:-}"               # VPN server IP (for kill switch)

# === NETWORK CONFIGURATION ===
# Interfaces are auto-detected at runtime if not provided via environment
LAN_IFACE="${LAN_IFACE:-}"                  # AP interface (auto-detect wireless)
WAN_IFACE="${WAN_IFACE:-}"                  # WAN/uplink interface (auto-detect wired)
AP_ADDR="${AP_ADDR:-10.5.5.1/24}"             # AP subnet
DHCP_RANGE="${DHCP_RANGE:-10.5.5.10,10.5.5.50,12h}"
USE_5GHZ="${USE_5GHZ:-true}"                     # Use 5GHz by default
SSID_PREFIX="${SSID_PREFIX:-SecureTravel}"       # WiFi network prefix
COUNTRY_CODE="${COUNTRY_CODE:-US}"               # Regulatory domain
HIDDEN_SSID="${HIDDEN_SSID:-false}"              # Hide SSID broadcast

# === SECURITY PATHS ===
HOSTAPD_CONF="${HOSTAPD_CONF:-/etc/hostapd/hostapd.conf}"
DNSMASQ_DROPIN="/etc/dnsmasq.d/router-secure.conf"
# shellcheck disable=SC2034
SURICATA_CONF="/etc/suricata/suricata.yaml"
STATE_DIR="/run/routerpi"
LOG_DIR="/var/log/routerpi"
CONFIG_DIR="/etc/routerpi"
# shellcheck disable=SC2034
BLOCKED_IPS_FILE="$STATE_DIR/blocked_ips"
WIFI_PASSWORD_FILE="$STATE_DIR/wifi_password"
SECURITY_LOG="$LOG_DIR/security.log"
# shellcheck disable=SC2034
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

# Auto-detect the most suitable WAN interface (prefer default route / wired)
detect_wan_interface() {
    local via_default
    via_default=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
    if [[ -n "$via_default" && -d "/sys/class/net/$via_default" ]]; then
        echo "$via_default"
        return 0
    fi
    # Common wired interface names
    for candidate in eth0 eno1 enp0s25 enp1s0; do
        if [[ -d "/sys/class/net/$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    # Fallback: first non-wireless interface
    for path in /sys/class/net/*; do
        local name
        name=$(basename "$path")
        [[ "$name" == lo ]] && continue
        if [[ ! -d "/sys/class/net/$name/wireless" ]]; then
            echo "$name"
            return 0
        fi
    done
    echo "eth0"
}

# Auto-detect the LAN/AP interface (prefer wireless)
detect_lan_interface() {
    # Prefer common wireless names if present
    for candidate in wlan0 wlan1; do
        if [[ -d "/sys/class/net/$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    # Predictable names
    for path in /sys/class/net/wlp* /sys/class/net/wlx*; do
        [[ -e "$path" ]] || continue
        basename "$path"
        return 0
    done
    # Fallback: first wireless interface
    for path in /sys/class/net/*; do
        local name
        name=$(basename "$path")
        [[ "$name" == lo ]] && continue
        if [[ -d "/sys/class/net/$name/wireless" ]]; then
            echo "$name"
            return 0
        fi
    done
    echo "wlan0"
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
    sleep 1  # Wait for interface to go down
    
    # Configure for AP mode
    iw dev "$iface" set type __ap 2>/dev/null || true
    
    # Set regulatory domain
    iw reg set "$COUNTRY_CODE" 2>/dev/null || true
    
    # Power management off for stability
    iw dev "$iface" set power_save off 2>/dev/null || true
    
    # Don't bring it up here - let the main function handle it with the IP
    # But ensure it's ready to be brought up
    
    log "✓ MT7612U interface configured"
}

# === WIREGUARD VPN FUNCTIONS ===
setup_wireguard_killswitch() {
    if [[ "$ENABLE_KILL_SWITCH" != "true" ]]; then
        return 0
    fi
    
    log "Setting up WireGuard kill switch..."
    
    # Allow local traffic
    iptables -I OUTPUT -o lo -j ACCEPT
    iptables -I OUTPUT -d 192.168.0.0/16 -j ACCEPT
    iptables -I OUTPUT -d 10.0.0.0/8 -j ACCEPT
    iptables -I OUTPUT -d 172.16.0.0/12 -j ACCEPT
    
    # Allow WireGuard server if specified
    if [[ -n "$VPN_SERVER_IP" ]]; then
        iptables -I OUTPUT -d "$VPN_SERVER_IP" -j ACCEPT
        log "✓ Kill switch allows VPN server: $VPN_SERVER_IP"
    fi
    
    # Allow established connections
    iptables -I OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Block everything else
    iptables -A OUTPUT -j LOG --log-prefix "KILL-SWITCH-DROP: " --log-level 4
    iptables -A OUTPUT -j DROP
    
    log "✓ WireGuard kill switch enabled"
}

disable_wireguard_killswitch() {
    log "Disabling WireGuard kill switch..."
    
    # Remove kill switch rules
    iptables -D OUTPUT -j DROP 2>/dev/null || true
    iptables -D OUTPUT -j LOG --log-prefix "KILL-SWITCH-DROP: " --log-level 4 2>/dev/null || true
    iptables -D OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -D OUTPUT -d 172.16.0.0/12 -j ACCEPT 2>/dev/null || true
    iptables -D OUTPUT -d 10.0.0.0/8 -j ACCEPT 2>/dev/null || true
    iptables -D OUTPUT -d 192.168.0.0/16 -j ACCEPT 2>/dev/null || true
    iptables -D OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    
    if [[ -n "$VPN_SERVER_IP" ]]; then
        iptables -D OUTPUT -d "$VPN_SERVER_IP" -j ACCEPT 2>/dev/null || true
    fi
    
    log "✓ WireGuard kill switch disabled"
}

start_wireguard() {
    if [[ "$ENABLE_VPN" != "true" ]]; then
        return 0
    fi
    
    if [[ ! -f "$VPN_CONFIG" ]]; then
        log "⚠ WireGuard config not found: $VPN_CONFIG"
        log "  Run: sudo ./scripts/vpn_setup.sh setup-wg client"
        return 0
    fi
    
    log "Starting WireGuard VPN..."
    
    # Enable kill switch first if enabled
    if [[ "$ENABLE_KILL_SWITCH" == "true" ]]; then
        setup_wireguard_killswitch
    fi
    
    # Start WireGuard
    local config_name
    config_name=$(basename "$VPN_CONFIG" .conf)
    
    if wg-quick up "$config_name" 2>/dev/null; then
        log "✓ WireGuard VPN connected"
        log_security "WireGuard VPN established with kill switch protection"
        
        # Verify connection
        if wg show | grep -q "interface:"; then
            log "✓ WireGuard interface active"
        fi
    else
        log "⚠ Failed to start WireGuard VPN"
        if [[ "$ENABLE_KILL_SWITCH" == "true" ]]; then
            log "⚠ Kill switch remains active - no internet access"
        fi
    fi
}

stop_wireguard() {
    log "Stopping WireGuard VPN..."
    
    # Stop all WireGuard interfaces
    for interface in $(wg show interfaces 2>/dev/null); do
        wg-quick down "$interface" 2>/dev/null || true
        log "✓ Stopped WireGuard interface: $interface"
    done
    
    # Disable kill switch
    disable_wireguard_killswitch
    
    log "✓ WireGuard VPN stopped"
}

check_wireguard_status() {
    if [[ "$ENABLE_VPN" != "true" ]]; then
        return 0
    fi
    
    echo "WireGuard VPN Status:"
    if command -v wg >/dev/null 2>&1; then
        if wg show 2>/dev/null | grep -q "interface:"; then
            echo "  ✅ Connected"
            wg show | head -10
        else
            echo "  ⚪ Disconnected"
        fi
    else
        echo "  ❌ WireGuard not installed"
    fi
    
    echo "Kill Switch Status:"
    if iptables -L OUTPUT | grep -q "DROP"; then
        echo "  🛡️ Active"
    else
        echo "  ⚪ Inactive"
    fi
    echo
}

# === SECURITY FUNCTIONS ===
setup_firewall() {
    log "Setting up advanced firewall rules..."
    
    # Use external script if available
    if [[ -f "$SCRIPT_DIR/configs/iptables_rules.sh" ]]; then
        # shellcheck disable=SC1091
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
        # Calculate and set broadcast address
        local broadcast_addr
        broadcast_addr=$(echo "${AP_ADDR%/*}" | sed 's/\.[0-9]*$/\.255/')
        sed -i "s/BROADCAST_PLACEHOLDER/$broadcast_addr/g" "$DNSMASQ_DROPIN"
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
    
    # Auto-detect interfaces if not provided
    if [[ -z "${WAN_IFACE}" ]]; then
        WAN_IFACE=$(detect_wan_interface)
        log "Detected WAN interface: ${WAN_IFACE}"
    fi
    if [[ -z "${LAN_IFACE}" ]]; then
        LAN_IFACE=$(detect_lan_interface)
        log "Detected LAN interface: ${LAN_IFACE}"
    fi
    
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
    
    # Kill any processes using the interface
    pkill -f "wpa_supplicant.*$LAN_IFACE" 2>/dev/null || true
    pkill -f "dhclient.*$LAN_IFACE" 2>/dev/null || true
    pkill -f "dhcpcd.*$LAN_IFACE" 2>/dev/null || true
    sleep 1
    
    # Set interface down and flush addresses
    ip link set "$LAN_IFACE" down 2>/dev/null || true
    sleep 2  # Wait for interface to fully go down
    ip addr flush dev "$LAN_IFACE" 2>/dev/null || true
    
    # For wireless interfaces, ensure proper mode
    if [[ -d "/sys/class/net/$LAN_IFACE/wireless" ]]; then
        # Set to unmanaged mode for NetworkManager
        if command -v nmcli >/dev/null 2>&1; then
            nmcli device set "$LAN_IFACE" managed no 2>/dev/null || true
        fi
        
        # Ensure interface is in AP mode
        iw dev "$LAN_IFACE" set type __ap 2>/dev/null || true
    fi
    
    # Configure IP address
    if ! ip addr add "$AP_ADDR" dev "$LAN_IFACE" 2>/dev/null; then
        log "Failed to add IP address, checking current addresses..."
        ip addr show "$LAN_IFACE"
        error "Failed to configure IP address on $LAN_IFACE"
    fi
    
    # Bring interface up
    if ! ip link set "$LAN_IFACE" up 2>/dev/null; then
        log "Failed to bring up interface, checking state..."
        ip link show "$LAN_IFACE"
        error "Failed to bring up $LAN_IFACE"
    fi
    
    # Ensure WAN interface is up
    ip link set "$WAN_IFACE" up 2>/dev/null || true

    # Wait and verify interfaces are ready
    sleep 3  # Wait for interfaces to be fully up

    # Verify LAN interface is ready
    local lan_state
    lan_state=$(cat /sys/class/net/"$LAN_IFACE"/operstate 2>/dev/null || echo "unknown")
    log "Interface $LAN_IFACE state: $lan_state"
    
    if [[ "$lan_state" != "up" ]] && [[ "$lan_state" != "unknown" ]]; then
        log "Warning: Interface $LAN_IFACE state is $lan_state, attempting recovery..."
        
        # Try resetting the interface
        ip link set "$LAN_IFACE" down
        sleep 2
        ip link set "$LAN_IFACE" up
        sleep 2
        
        # Check again
        lan_state=$(cat /sys/class/net/"$LAN_IFACE"/operstate 2>/dev/null || echo "unknown")
        if [[ "$lan_state" != "up" ]] && [[ "$lan_state" != "unknown" ]]; then
            log "ERROR: Interface $LAN_IFACE failed to come up (state: $lan_state)"
        fi
    fi

    # Verify the IP was assigned
    if ! ip addr show "$LAN_IFACE" | grep -q "${AP_ADDR%/*}"; then
        log "ERROR: IP address not properly assigned to $LAN_IFACE"
        ip addr show "$LAN_IFACE"
    else
        log "✓ IP address ${AP_ADDR} assigned to $LAN_IFACE"
    fi

    log "✓ Network interfaces configured"
    
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
    
    # Check if systemctl is available (systemd)
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        # Stop services first to ensure clean state
        systemctl stop dnsmasq 2>/dev/null || true
        systemctl stop hostapd 2>/dev/null || true
        sleep 1
        
        # Start dnsmasq
        if ! systemctl restart dnsmasq; then
            log "ERROR: Failed to start dnsmasq via systemctl"
            log "Checking dnsmasq configuration..."
            dnsmasq --test -C "$DNSMASQ_DROPIN" 2>&1 | tee -a "$LOG_DIR/router.log"
            
            # Try starting dnsmasq directly
            log "Attempting to start dnsmasq directly..."
            pkill dnsmasq 2>/dev/null || true
            sleep 1
            if dnsmasq -C "$DNSMASQ_DROPIN"; then
                log "✓ dnsmasq started directly"
            else
                log "ERROR: dnsmasq failed to start"
                error "dnsmasq startup failed. Check logs at $LOG_DIR/router.log"
            fi
        fi
        
        # Start hostapd
        if ! systemctl restart hostapd; then
            log "ERROR: Failed to start hostapd via systemctl"
            log "Checking hostapd configuration..."
            hostapd -dd "$HOSTAPD_CONF" -t 2>&1 | head -20 | tee -a "$LOG_DIR/router.log"
            
            # Try starting hostapd directly
            log "Attempting to start hostapd directly..."
            pkill hostapd 2>/dev/null || true
            sleep 1
            hostapd -B "$HOSTAPD_CONF"
            if [[ $? -ne 0 ]]; then
                log "ERROR: hostapd failed to start"
                error "hostapd startup failed. Check logs at $LOG_DIR/router.log"
            fi
        fi
    else
        # Non-systemd environment, start services directly
        log "Starting services directly (non-systemd environment)..."
        
        # Start dnsmasq
        pkill dnsmasq 2>/dev/null || true
        sleep 1
        
        # Test configuration first
        if ! dnsmasq --test -C "$DNSMASQ_DROPIN"; then
            log "ERROR: dnsmasq configuration test failed"
            error "Invalid dnsmasq configuration"
        fi
        
        # Start dnsmasq in background
        dnsmasq -C "$DNSMASQ_DROPIN"
        if [[ $? -ne 0 ]]; then
            log "ERROR: Failed to start dnsmasq"
            error "dnsmasq startup failed"
        fi
        log "✓ dnsmasq started successfully"
        
        # Start hostapd
        pkill hostapd 2>/dev/null || true
        sleep 1
        
        # Test configuration first
        if ! hostapd -t "$HOSTAPD_CONF" >/dev/null 2>&1; then
            log "ERROR: hostapd configuration test failed"
            hostapd -dd "$HOSTAPD_CONF" -t 2>&1 | head -20 | tee -a "$LOG_DIR/router.log"
            error "Invalid hostapd configuration"
        fi
        
        # Start hostapd in background
        hostapd -B "$HOSTAPD_CONF"
        if [[ $? -ne 0 ]]; then
            log "ERROR: Failed to start hostapd"
            error "hostapd startup failed"
        fi
        log "✓ hostapd started successfully"
    fi
    
    # Start WireGuard VPN if enabled
    start_wireguard
    
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
    
    # Stop WireGuard VPN
    stop_wireguard
    
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
    
    # Reset interfaces
    if [[ -f "$STATE_DIR/lan_interface" ]]; then
        local lan_iface
        lan_iface=$(cat "$STATE_DIR/lan_interface")
        log "Resetting LAN interface: $lan_iface"
    
        # Remove IP and bring down
        ip addr flush dev "$lan_iface" 2>/dev/null || true
        ip link set "$lan_iface" down 2>/dev/null || true
    
        # Reset to managed mode (for WiFi adapters)
        iw dev "$lan_iface" set type managed 2>/dev/null || true
    fi

    # Reset WAN interface if needed
    if [[ -f "$STATE_DIR/wan_interface" ]]; then
        local wan_iface
        wan_iface=$(cat "$STATE_DIR/wan_interface")
        log "Resetting WAN interface: $wan_iface"
    
        # Don't bring WAN down - just ensure it's properly configured for normal use
        # The system's network manager should handle it
    
        # If using DHCP, renew the lease
        if command -v dhclient >/dev/null 2>&1; then
            dhclient -r "$wan_iface" 2>/dev/null || true
            dhclient "$wan_iface" 2>/dev/null || true
        elif command -v dhcpcd >/dev/null 2>&1; then
            dhcpcd -n "$wan_iface" 2>/dev/null || true
        fi
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
    
    # WireGuard VPN status
    echo
    check_wireguard_status
    
    # Connected clients
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
    echo "  Firewall: $(iptables -L INPUT | grep -q 'DROP' && echo ACTIVE || echo INACTIVE)"
    echo "  DNS Security: $(systemctl is-active dnsmasq 2>/dev/null || echo inactive)"
    
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
    $SCRIPT_NAME {start|stop|status|monitor|audit|reset|vpn-start|vpn-stop|vpn-status|help}

COMMANDS:
    start      Start secure router mode (includes WireGuard VPN if enabled)
    stop       Stop router mode and restore normal operation
    status     Show current router status and configuration
    monitor    Real-time monitoring dashboard
    audit      Run security audit and show recommendations
    reset      Reset MT7612U adapter (useful for troubleshooting)
    vpn-start  Start WireGuard VPN with kill switch
    vpn-stop   Stop WireGuard VPN and disable kill switch
    vpn-status Show WireGuard VPN connection status
    help       Show this help message

ENVIRONMENT VARIABLES:
    WAN_IFACE         WAN interface (auto-detected by default)
    LAN_IFACE         LAN/AP interface (default: wlan0)
    AP_ADDR           Router IP and subnet (default: 192.168.8.1/24)
    USE_5GHZ          Use 5GHz band (default: true)
    SECURITY_MODE     Security level: high|medium|low (default: high)
    ENABLE_VPN        Enable WireGuard VPN (default: false)
    ENABLE_KILL_SWITCH Enable VPN kill switch (default: true)
    VPN_CONFIG        WireGuard config file path
    VPN_SERVER_IP     VPN server IP for kill switch

EXAMPLES:
    # Start with 2.4GHz
    USE_5GHZ=false sudo $SCRIPT_NAME start
    
    # Use custom IP range
    AP_ADDR="10.0.0.1/24" sudo $SCRIPT_NAME start
    
    # Start with WireGuard VPN enabled
    ENABLE_VPN=true sudo $SCRIPT_NAME start
    
    # Start VPN only
    sudo $SCRIPT_NAME vpn-start

SECURITY FEATURES:
    ✅ Advanced stateful firewall with DDoS protection
    ✅ WPA2/WPA3 encryption with strong password generation
    ✅ DNS security with malware domain blocking
    ✅ Client isolation and AP security hardening
    ✅ WireGuard VPN with integrated kill switch
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
    vpn-start)
        check_root
        start_wireguard
        ;;
    vpn-stop)
        check_root
        stop_wireguard
        ;;
    vpn-status)
        check_wireguard_status
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
