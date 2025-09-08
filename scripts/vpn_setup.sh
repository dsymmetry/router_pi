#!/bin/bash
#===============================================================================
# VPN Setup Script for RPi5 Secure Router
# Configure WireGuard VPN client connections (primary VPN solution)
#===============================================================================

set -euo pipefail

# shellcheck disable=SC2034
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/routerpi"
VPN_LOG="$LOG_DIR/vpn.log"
VPN_CONFIG_DIR="/etc/routerpi/vpn"

# Create directories
mkdir -p "$LOG_DIR" "$VPN_CONFIG_DIR" 2>/dev/null || true

log_vpn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] VPN: $*" | tee -a "$VPN_LOG"
}

check_vpn_support() {
    echo "🔍 Checking VPN Support"
    echo "======================"
    
    # Check for WireGuard
    if command -v wg >/dev/null 2>&1; then
        echo "✅ WireGuard client available"
        local wg_version
        wg_version=$(wg --version 2>/dev/null | head -1 || echo "unknown")
        echo "   Version: $wg_version"
    else
        echo "⚠️ WireGuard not installed"
        echo "   Install with: apt-get install wireguard"
    fi
    
    # Check for legacy OpenVPN (deprecated)
    if command -v openvpn >/dev/null 2>&1; then
        echo "ℹ️ OpenVPN client detected (legacy support only)"
        local ovpn_version
        ovpn_version=$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
        echo "   Version: $ovpn_version"
        echo "   Note: WireGuard is now the primary VPN solution"
    else
        echo "ℹ️ OpenVPN not installed (WireGuard is recommended)"
    fi
    
    # Check kernel modules
    echo
    echo "Kernel module support:"
    
    if lsmod | grep -q "^wireguard"; then
        echo "✅ WireGuard kernel module loaded"
    elif modinfo wireguard >/dev/null 2>&1; then
        echo "⚠️ WireGuard kernel module available but not loaded"
    else
        echo "❌ WireGuard kernel module not available"
    fi
    
    if lsmod | grep -q "^tun"; then
        echo "✅ TUN/TAP kernel module loaded"
    else
        echo "❌ TUN/TAP kernel module not loaded"
        echo "   Load with: modprobe tun"
    fi
    
    echo
}

install_vpn_clients() {
    echo "📦 Installing VPN Clients"
    echo "========================"
    
    if [[ $EUID -ne 0 ]]; then
        echo "❌ This function requires root privileges"
        return 1
    fi
    
    echo "Updating package lists..."
    apt-get update
    
    echo "Installing WireGuard (primary VPN)..."
    if apt-get install -y wireguard wireguard-tools; then
        echo "✅ WireGuard installed successfully"
    else
        echo "❌ Failed to install WireGuard"
    fi
    
    echo "Installing legacy OpenVPN support (optional)..."
    if apt-get install -y openvpn openvpn-systemd-resolved; then
        echo "ℹ️ OpenVPN installed (legacy support only)"
        echo "   Note: WireGuard is the recommended VPN solution"
    else
        echo "⚠️ Failed to install OpenVPN (not critical)"
    fi
    
    echo "Loading kernel modules..."
    modprobe tun 2>/dev/null || echo "⚠️ Failed to load TUN module"
    modprobe wireguard 2>/dev/null || echo "⚠️ Failed to load WireGuard module"
    
    echo "✅ VPN client installation completed"
    log_vpn "VPN clients installed"
}

setup_wireguard() {
    local config_name="${1:-client}"
    local config_file="$VPN_CONFIG_DIR/${config_name}.conf"
    
    echo "🔧 Setting up WireGuard Configuration"
    echo "===================================="
    
    if [[ ! -f "$config_file" ]]; then
        echo "Creating WireGuard configuration template..."
        
        # Generate key pair
        local private_key public_key
        private_key=$(wg genkey)
        public_key=$(echo "$private_key" | wg pubkey)
        
        cat > "$config_file" << EOF
[Interface]
# Client private key (keep this secret!)
PrivateKey = $private_key
# Client IP address (get this from your VPN provider)
Address = 10.0.0.2/32
# DNS servers to use through VPN
DNS = 1.1.1.1, 1.0.0.1

[Peer]
# Server public key (get this from your VPN provider)
PublicKey = SERVER_PUBLIC_KEY_HERE
# Server endpoint (get this from your VPN provider)
Endpoint = vpn.example.com:51820
# Allowed IPs (0.0.0.0/0 routes all traffic through VPN)
AllowedIPs = 0.0.0.0/0
# Keep connection alive
PersistentKeepalive = 25
EOF
        
        chmod 600 "$config_file"
        
        echo "✅ WireGuard configuration created: $config_file"
        echo "📋 Your public key: $public_key"
        echo
        echo "⚠️  IMPORTANT: Edit $config_file and:"
        echo "   1. Replace SERVER_PUBLIC_KEY_HERE with your server's public key"
        echo "   2. Replace vpn.example.com:51820 with your server's endpoint"
        echo "   3. Update the Address if different from 10.0.0.2/32"
        echo "   4. Share your public key with your VPN provider"
    else
        echo "✅ WireGuard configuration already exists: $config_file"
    fi
    
    echo
    echo "To connect:"
    echo "  sudo wg-quick up $config_name"
    echo "To disconnect:"
    echo "  sudo wg-quick down $config_name"
    echo "To check status:"
    echo "  sudo wg show"
    
    log_vpn "WireGuard configuration created: $config_name"
}

setup_openvpn() {
    local config_name="${1:-client}"
    local config_file="$VPN_CONFIG_DIR/${config_name}.ovpn"
    
    echo "🔧 Setting up OpenVPN Configuration"
    echo "=================================="
    
    if [[ ! -f "$config_file" ]]; then
        echo "Creating OpenVPN configuration template..."
        
        cat > "$config_file" << 'EOF'
# OpenVPN Client Configuration Template
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun

# Security settings
cipher AES-256-CBC
auth SHA256
key-direction 1
remote-cert-tls server
tls-version-min 1.2

# Compression and performance
comp-lzo
verb 3

# DNS settings
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1

# Prevent DNS leaks
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf

# Authentication (uncomment one method)
# auth-user-pass auth.txt  # For username/password auth
# cert client.crt          # For certificate auth
# key client.key

# Certificate Authority
# ca ca.crt

# TLS authentication key
# tls-auth ta.key 1
EOF
        
        chmod 600 "$config_file"
        
        echo "✅ OpenVPN configuration template created: $config_file"
        echo
        echo "⚠️  IMPORTANT: Edit $config_file and:"
        echo "   1. Replace vpn.example.com:1194 with your server's endpoint"
        echo "   2. Add your certificate files (ca.crt, client.crt, client.key)"
        echo "   3. Configure authentication method"
        echo "   4. Update any provider-specific settings"
    else
        echo "✅ OpenVPN configuration already exists: $config_file"
    fi
    
    # Create auth file template if using password auth
    local auth_file="$VPN_CONFIG_DIR/${config_name}_auth.txt"
    if [[ ! -f "$auth_file" ]]; then
        cat > "$auth_file" << 'EOF'
username_here
password_here
EOF
        chmod 600 "$auth_file"
        echo "📝 Auth file template created: $auth_file"
    fi
    
    echo
    echo "To connect:"
    echo "  sudo openvpn --config $config_file"
    echo "To connect as daemon:"
    echo "  sudo openvpn --config $config_file --daemon"
    echo "To stop daemon:"
    echo "  sudo pkill openvpn"
    
    log_vpn "OpenVPN configuration created: $config_name"
}

connect_vpn() {
    local vpn_type="${1:-wireguard}"
    local config_name="${2:-client}"
    
    # Warn if using deprecated OpenVPN
    if [[ "$vpn_type" == "openvpn" ]] || [[ "$vpn_type" == "ovpn" ]]; then
        echo "⚠️ WARNING: OpenVPN is deprecated. WireGuard is recommended for better security and performance."
        echo "   Consider migrating to WireGuard: ./vpn_setup.sh setup-wg"
        echo
    fi
    
    echo "🔌 Connecting to VPN"
    echo "==================="
    
    case "$vpn_type" in
        "wireguard"|"wg")
            local config_file="$VPN_CONFIG_DIR/${config_name}.conf"
            
            if [[ ! -f "$config_file" ]]; then
                echo "❌ WireGuard configuration not found: $config_file"
                return 1
            fi
            
            echo "Connecting to WireGuard VPN..."
            if wg-quick up "$config_name"; then
                echo "✅ WireGuard VPN connected"
                log_vpn "WireGuard VPN connected: $config_name"
            else
                echo "❌ Failed to connect WireGuard VPN"
                return 1
            fi
            ;;
            
        "openvpn"|"ovpn")
            local config_file="$VPN_CONFIG_DIR/${config_name}.ovpn"
            
            if [[ ! -f "$config_file" ]]; then
                echo "❌ OpenVPN configuration not found: $config_file"
                return 1
            fi
            
            echo "Connecting to OpenVPN..."
            if openvpn --config "$config_file" --daemon; then
                echo "✅ OpenVPN connected"
                log_vpn "OpenVPN connected: $config_name"
            else
                echo "❌ Failed to connect OpenVPN"
                return 1
            fi
            ;;
            
        *)
            echo "❌ Unknown VPN type: $vpn_type"
            echo "   Primary: wireguard (recommended)"
            echo "   Legacy: openvpn (deprecated)"
            return 1
            ;;
    esac
}

disconnect_vpn() {
    local vpn_type="${1:-auto}"
    local config_name="${2:-client}"
    
    echo "🔌 Disconnecting VPN"
    echo "===================="
    
    if [[ "$vpn_type" == "auto" ]]; then
        # Try to detect and disconnect all VPN types
        
        # Check WireGuard
        if wg show 2>/dev/null | grep -q "interface:"; then
            echo "Disconnecting WireGuard..."
            wg-quick down "$config_name" 2>/dev/null || true
        fi
        
        # Check OpenVPN
        if pgrep openvpn >/dev/null; then
            echo "Disconnecting OpenVPN..."
            pkill openvpn
        fi
        
        echo "✅ All VPN connections disconnected"
        log_vpn "All VPN connections disconnected"
        
    elif [[ "$vpn_type" == "wireguard" ]] || [[ "$vpn_type" == "wg" ]]; then
        echo "Disconnecting WireGuard..."
        if wg-quick down "$config_name"; then
            echo "✅ WireGuard disconnected"
            log_vpn "WireGuard disconnected: $config_name"
        else
            echo "❌ Failed to disconnect WireGuard"
        fi
        
    elif [[ "$vpn_type" == "openvpn" ]] || [[ "$vpn_type" == "ovpn" ]]; then
        echo "Disconnecting OpenVPN..."
        if pkill openvpn; then
            echo "✅ OpenVPN disconnected"
            log_vpn "OpenVPN disconnected"
        else
            echo "❌ No OpenVPN process found"
        fi
    fi
}

check_vpn_status() {
    echo "📊 VPN Status"
    echo "============="
    
    # Check WireGuard
    if command -v wg >/dev/null 2>&1; then
        echo "WireGuard status:"
        if wg show 2>/dev/null | grep -q "interface:"; then
            wg show
        else
            echo "  ⚪ No active WireGuard connections"
        fi
    fi
    
    echo
    
    # Check OpenVPN
    if pgrep openvpn >/dev/null; then
        echo "✅ OpenVPN is running"
        local ovpn_pids
        ovpn_pids=$(pgrep openvpn | tr '\n' ' ')
        echo "  PIDs: $ovpn_pids"
    else
        echo "⚪ OpenVPN is not running"
    fi
    
    echo
    
    # Check public IP
    echo "Public IP check:"
    if command -v curl >/dev/null 2>&1; then
        local public_ip
        public_ip=$(curl -s --connect-timeout 5 http://httpbin.org/ip 2>/dev/null | grep -o '"origin": "[^"]*' | cut -d'"' -f4 || echo "unknown")
        echo "  Current public IP: $public_ip"
    else
        echo "  ❌ Cannot check public IP (curl not available)"
    fi
    
    # Check DNS leaks
    echo
    echo "DNS leak test:"
    if command -v dig >/dev/null 2>&1; then
        local dns_server
        dns_server=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null || echo "unknown")
        echo "  DNS-resolved IP: $dns_server"
        
        if [[ "$dns_server" != "unknown" ]] && [[ "$public_ip" != "unknown" ]]; then
            if [[ "$dns_server" == "$public_ip" ]]; then
                echo "  ✅ No DNS leak detected"
            else
                echo "  ⚠️ Possible DNS leak detected"
            fi
        fi
    fi
}

setup_kill_switch() {
    echo "🛡️ Setting up VPN Kill Switch"
    echo "============================="
    
    if [[ $EUID -ne 0 ]]; then
        echo "❌ Kill switch setup requires root privileges"
        return 1
    fi
    
    # Create kill switch script
    local kill_switch_script="/etc/routerpi/vpn_kill_switch.sh"
    
    cat > "$kill_switch_script" << 'EOF'
#!/bin/bash
# VPN Kill Switch - Block traffic when VPN is down

set -euo pipefail

LOG_FILE="/var/log/routerpi/vpn_kill_switch.log"

log_kill_switch() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] KILL_SWITCH: $*" | tee -a "$LOG_FILE"
}

enable_kill_switch() {
    log_kill_switch "Enabling VPN kill switch"
    
    # Block all traffic except local and VPN server
    iptables -I OUTPUT -o lo -j ACCEPT
    iptables -I OUTPUT -d 192.168.0.0/16 -j ACCEPT
    iptables -I OUTPUT -d 10.0.0.0/8 -j ACCEPT
    iptables -I OUTPUT -d 172.16.0.0/12 -j ACCEPT
    
    # Allow VPN server (update with your server IP)
    # iptables -I OUTPUT -d VPN_SERVER_IP -j ACCEPT
    
    # Block everything else
    iptables -I OUTPUT -j DROP
    
    log_kill_switch "Kill switch enabled"
}

disable_kill_switch() {
    log_kill_switch "Disabling VPN kill switch"
    
    # Remove kill switch rules
    iptables -D OUTPUT -j DROP 2>/dev/null || true
    iptables -D OUTPUT -d 172.16.0.0/12 -j ACCEPT 2>/dev/null || true
    iptables -D OUTPUT -d 10.0.0.0/8 -j ACCEPT 2>/dev/null || true
    iptables -D OUTPUT -d 192.168.0.0/16 -j ACCEPT 2>/dev/null || true
    iptables -D OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    
    log_kill_switch "Kill switch disabled"
}

case "${1:-}" in
    enable)
        enable_kill_switch
        ;;
    disable)
        disable_kill_switch
        ;;
    *)
        echo "Usage: $0 {enable|disable}"
        exit 1
        ;;
esac
EOF
    
    chmod +x "$kill_switch_script"
    
    echo "✅ VPN kill switch script created: $kill_switch_script"
    echo
    echo "To enable kill switch:"
    echo "  sudo $kill_switch_script enable"
    echo "To disable kill switch:"
    echo "  sudo $kill_switch_script disable"
    
    log_vpn "VPN kill switch script created"
}

show_help() {
    cat << EOF
VPN Setup Script for RPi5 Secure Router

USAGE:
    $0 {check|install|setup-wg|setup-ovpn|connect|disconnect|status|kill-switch|help} [options]

COMMANDS:
    check           Check VPN support and requirements
    install         Install VPN clients (requires root)
    setup-wg [name] Setup WireGuard configuration (recommended)
    setup-ovpn [name] Setup OpenVPN configuration (legacy)
    connect <type> [name] Connect to VPN (wireguard recommended, openvpn legacy)
    disconnect [type] [name] Disconnect VPN
    status          Show VPN connection status
    kill-switch     Setup VPN kill switch (integrated with WireGuard)
    help            Show this help message

EXAMPLES:
    $0 check                    # Check VPN support
    $0 setup-wg myvpn          # Setup WireGuard config (recommended)
    $0 connect wireguard myvpn  # Connect to WireGuard
    $0 status                   # Check VPN status
    $0 disconnect              # Disconnect all VPNs

CONFIGURATION FILES:
    WireGuard: $VPN_CONFIG_DIR/[name].conf (recommended)
    OpenVPN:   $VPN_CONFIG_DIR/[name].ovpn (legacy)

NOTES:
    - WireGuard is the primary VPN solution (faster, more secure)
    - OpenVPN support is maintained for legacy compatibility only
    - VPN configurations are stored in $VPN_CONFIG_DIR
    - Kill switch is integrated with the main router script
    - WireGuard provides better performance and security than OpenVPN
EOF
}

# Main execution
case "${1:-help}" in
    check)
        check_vpn_support
        ;;
    install)
        install_vpn_clients
        ;;
    setup-wg)
        setup_wireguard "${2:-client}"
        ;;
    setup-ovpn)
        setup_openvpn "${2:-client}"
        ;;
    connect)
        connect_vpn "${2:-wireguard}" "${3:-client}"
        ;;
    disconnect)
        disconnect_vpn "${2:-auto}" "${3:-client}"
        ;;
    status)
        check_vpn_status
        ;;
    kill-switch)
        setup_kill_switch
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

