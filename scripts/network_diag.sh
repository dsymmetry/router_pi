#!/bin/bash
#===============================================================================
# Network Diagnostics Script for RPi5 Secure Router
# Comprehensive network troubleshooting and monitoring tools
#===============================================================================

set -euo pipefail

# shellcheck disable=SC2034
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/routerpi"
DIAG_LOG="$LOG_DIR/network_diag.log"

# Create directories
mkdir -p "$LOG_DIR" 2>/dev/null || true

log_diag() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] DIAG: $*" | tee -a "$DIAG_LOG"
}

check_interfaces() {
    echo "🌐 Network Interface Analysis"
    echo "============================"
    
    # List all interfaces
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+" | while read -r line; do
        local iface
        iface=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        local state
        state=$(echo "$line" | grep -o "state [A-Z]*" | cut -d' ' -f2)
        echo "  $iface: $state"
    done
    
    echo
    
    # Check specific interfaces
    local wan_iface lan_iface
    wan_iface=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}' || echo "unknown")
    lan_iface="wlan0"  # Default AP interface
    
    echo "Interface details:"
    for iface in "$wan_iface" "$lan_iface"; do
        if [[ "$iface" != "unknown" ]] && [[ -d "/sys/class/net/$iface" ]]; then
            echo "  $iface:"
            echo "    Status: $(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")"
            echo "    MAC: $(cat "/sys/class/net/$iface/address" 2>/dev/null || echo "unknown")"
            echo "    MTU: $(cat "/sys/class/net/$iface/mtu" 2>/dev/null || echo "unknown")"
            
            # Get IP addresses
            local ips
            ips=$(ip -4 addr show "$iface" 2>/dev/null | grep inet | awk '{print $2}' | tr '\n' ' ')
            if [[ -n "$ips" ]]; then
                echo "    IPs: $ips"
            else
                echo "    IPs: none"
            fi
        fi
    done
    
    echo
}

check_routing() {
    echo "🛣️ Routing Table Analysis"
    echo "========================"
    
    echo "IPv4 routing table:"
    ip -4 route show | while read -r route; do
        echo "  $route"
    done
    
    echo
    
    # Check default gateway
    local default_gw
    default_gw=$(ip route | awk '/default/ {print $3; exit}')
    if [[ -n "$default_gw" ]]; then
        echo "Default gateway: $default_gw"
        
        # Test gateway connectivity
        if ping -c 2 -W 2 "$default_gw" >/dev/null 2>&1; then
            echo "✅ Gateway is reachable"
        else
            echo "❌ Gateway is not reachable"
        fi
    else
        echo "❌ No default gateway found"
    fi
    
    echo
}

check_dns() {
    echo "🔍 DNS Configuration Analysis"
    echo "============================"
    
    # Check resolv.conf
    if [[ -f /etc/resolv.conf ]]; then
        echo "DNS servers from /etc/resolv.conf:"
        grep "^nameserver" /etc/resolv.conf | while read -r line; do
            local dns_server
            dns_server=$(echo "$line" | awk '{print $2}')
            echo "  $dns_server"
            
            # Test DNS server
            if dig +short +time=2 google.com @"$dns_server" >/dev/null 2>&1; then
                echo "    ✅ Responding"
            else
                echo "    ❌ Not responding"
            fi
        done
    else
        echo "❌ /etc/resolv.conf not found"
    fi
    
    echo
    
    # Test common DNS queries
    echo "DNS resolution tests:"
    local test_domains=("google.com" "cloudflare.com" "github.com")
    
    for domain in "${test_domains[@]}"; do
        if dig +short +time=3 "$domain" >/dev/null 2>&1; then
            echo "  ✅ $domain resolves"
        else
            echo "  ❌ $domain fails to resolve"
        fi
    done
    
    echo
}

check_connectivity() {
    echo "🌍 Internet Connectivity Analysis"
    echo "================================="
    
    # Test connectivity to various targets
    local test_targets=(
        "1.1.1.1:Cloudflare DNS"
        "8.8.8.8:Google DNS"
        "9.9.9.9:Quad9 DNS"
        "google.com:Google"
    )
    
    for target_desc in "${test_targets[@]}"; do
        local target="${target_desc%:*}"
        local desc="${target_desc#*:}"
        
        if ping -c 2 -W 3 "$target" >/dev/null 2>&1; then
            echo "  ✅ $desc ($target) reachable"
        else
            echo "  ❌ $desc ($target) unreachable"
        fi
    done
    
    echo
    
    # Test HTTP connectivity
    echo "HTTP connectivity test:"
    if curl -s --connect-timeout 5 http://httpbin.org/ip >/dev/null 2>&1; then
        echo "  ✅ HTTP connectivity working"
        local public_ip
        public_ip=$(curl -s --connect-timeout 5 http://httpbin.org/ip | grep -o '"origin": "[^"]*' | cut -d'"' -f4)
        echo "  Public IP: ${public_ip:-unknown}"
    else
        echo "  ❌ HTTP connectivity failed"
    fi
    
    echo
}

check_firewall() {
    echo "🛡️ Firewall Status Analysis"
    echo "=========================="
    
    if ! command -v iptables >/dev/null 2>&1; then
        echo "❌ iptables not found"
        return 1
    fi
    
    # Check policies
    echo "Default policies:"
    local input_policy forward_policy output_policy
    input_policy=$(iptables -L INPUT | head -1 | awk '{print $4}' | tr -d '()')
    forward_policy=$(iptables -L FORWARD | head -1 | awk '{print $4}' | tr -d '()')
    output_policy=$(iptables -L OUTPUT | head -1 | awk '{print $4}' | tr -d '()')
    
    echo "  INPUT: $input_policy"
    echo "  FORWARD: $forward_policy"
    echo "  OUTPUT: $output_policy"
    
    echo
    
    # Count rules
    local input_rules forward_rules nat_rules
    input_rules=$(iptables -L INPUT --line-numbers | tail -n +3 | wc -l)
    forward_rules=$(iptables -L FORWARD --line-numbers | tail -n +3 | wc -l)
    nat_rules=$(iptables -t nat -L POSTROUTING --line-numbers | tail -n +3 | wc -l)
    
    echo "Rule counts:"
    echo "  INPUT rules: $input_rules"
    echo "  FORWARD rules: $forward_rules"
    echo "  NAT rules: $nat_rules"
    
    echo
    
    # Check NAT functionality
    if iptables -t nat -L POSTROUTING | grep -q "MASQUERADE"; then
        echo "✅ NAT masquerading configured"
    else
        echo "❌ NAT masquerading not found"
    fi
    
    echo
}

check_services() {
    echo "🔧 Service Status Analysis"
    echo "========================="
    
    local services=("hostapd" "dnsmasq" "ssh" "systemd-networkd" "NetworkManager")
    
    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "^$service"; then
            local status
            status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
            local enabled
            enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")
            
            case "$status" in
                "active") echo "  ✅ $service: $status ($enabled)" ;;
                "inactive") echo "  ⚪ $service: $status ($enabled)" ;;
                *) echo "  ❓ $service: $status ($enabled)" ;;
            esac
        else
            echo "  ➖ $service: not installed"
        fi
    done
    
    echo
}

check_wireless() {
    echo "📶 Wireless Status Analysis"
    echo "=========================="
    
    if ! command -v iw >/dev/null 2>&1; then
        echo "❌ iw command not found"
        return 1
    fi
    
    # List wireless interfaces
    echo "Wireless interfaces:"
    iw dev 2>/dev/null | grep Interface | while read -r line; do
        local iface
        iface=$(echo "$line" | awk '{print $2}')
        echo "  $iface"
        
        # Get interface info
        local info
        info=$(iw dev "$iface" info 2>/dev/null)
        if [[ -n "$info" ]]; then
            local type channel
            type=$(echo "$info" | grep "type" | awk '{print $2}')
            channel=$(echo "$info" | grep "channel" | awk '{print $2}')
            echo "    Type: ${type:-unknown}"
            echo "    Channel: ${channel:-unknown}"
        fi
        
        # Check for connected stations (if AP mode)
        if echo "$info" | grep -q "type AP"; then
            local station_count
            station_count=$(iw dev "$iface" station dump 2>/dev/null | grep -c "Station" || echo "0")
            echo "    Connected clients: $station_count"
        fi
    done
    
    echo
}

check_performance() {
    echo "📊 Performance Analysis"
    echo "======================"
    
    # CPU usage
    local cpu_usage
    cpu_usage=$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {printf "%.1f", usage}')
    echo "CPU usage: ${cpu_usage}%"
    
    # Memory usage
    local mem_info
    mem_info=$(free | grep Mem)
    local mem_total mem_used mem_free
    mem_total=$(echo "$mem_info" | awk '{print $2}')
    mem_used=$(echo "$mem_info" | awk '{print $3}')
    mem_free=$(echo "$mem_info" | awk '{print $4}')
    local mem_percent
    mem_percent=$(awk "BEGIN {printf \"%.1f\", $mem_used/$mem_total*100}")
    echo "Memory usage: ${mem_percent}% (${mem_used}/${mem_total}) - Free: ${mem_free}"
    
    # Temperature (if available)
    if command -v vcgencmd >/dev/null 2>&1; then
        local temp
        temp=$(vcgencmd measure_temp 2>/dev/null | cut -d= -f2 || echo "unknown")
        echo "Temperature: $temp"
    fi
    
    # Load average
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | tr -d ' ')
    echo "Load average: $load_avg"
    
    echo
}

run_speed_test() {
    echo "🚀 Network Speed Test"
    echo "===================="
    
    # Simple bandwidth test using curl
    echo "Testing download speed..."
    if command -v curl >/dev/null 2>&1; then
        local start_time end_time duration speed
        start_time=$(date +%s)
        
        # Download a small file and measure time
        if curl -s --connect-timeout 10 --max-time 30 -o /dev/null http://speedtest.wdc01.softlayer.com/downloads/test10.zip; then
            end_time=$(date +%s)
            duration=$((end_time - start_time))
            # Approximate speed (10MB file)
            speed=$(awk "BEGIN {printf \"%.1f\", 10*8/$duration}")
            echo "  Approximate speed: ${speed} Mbps"
        else
            echo "  ❌ Speed test failed"
        fi
    else
        echo "  ❌ curl not available for speed test"
    fi
    
    echo
}

monitor_traffic() {
    echo "📈 Real-time Traffic Monitor"
    echo "============================"
    echo "Press Ctrl+C to stop"
    echo
    
    local wan_iface lan_iface
    wan_iface=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}' || echo "unknown")
    lan_iface="wlan0"
    
    # Initial values
    local prev_wan_rx prev_wan_tx prev_lan_rx prev_lan_tx
    if [[ "$wan_iface" != "unknown" ]] && [[ -d "/sys/class/net/$wan_iface" ]]; then
        prev_wan_rx=$(cat "/sys/class/net/$wan_iface/statistics/rx_bytes" 2>/dev/null || echo "0")
        prev_wan_tx=$(cat "/sys/class/net/$wan_iface/statistics/tx_bytes" 2>/dev/null || echo "0")
    fi
    
    if [[ -d "/sys/class/net/$lan_iface" ]]; then
        prev_lan_rx=$(cat "/sys/class/net/$lan_iface/statistics/rx_bytes" 2>/dev/null || echo "0")
        prev_lan_tx=$(cat "/sys/class/net/$lan_iface/statistics/tx_bytes" 2>/dev/null || echo "0")
    fi
    
    while true; do
        sleep 2
        clear
        
        echo "=== Traffic Monitor - $(date) ==="
        echo
        
        # WAN interface
        if [[ "$wan_iface" != "unknown" ]] && [[ -d "/sys/class/net/$wan_iface" ]]; then
            local wan_rx wan_tx wan_rx_rate wan_tx_rate
            wan_rx=$(cat "/sys/class/net/$wan_iface/statistics/rx_bytes" 2>/dev/null || echo "0")
            wan_tx=$(cat "/sys/class/net/$wan_iface/statistics/tx_bytes" 2>/dev/null || echo "0")
            
            wan_rx_rate=$(( (wan_rx - prev_wan_rx) / 2 / 1024 ))
            wan_tx_rate=$(( (wan_tx - prev_wan_tx) / 2 / 1024 ))
            
            echo "WAN ($wan_iface):"
            echo "  RX: $((wan_rx/1024/1024))MB total, ${wan_rx_rate}KB/s"
            echo "  TX: $((wan_tx/1024/1024))MB total, ${wan_tx_rate}KB/s"
            
            prev_wan_rx=$wan_rx
            prev_wan_tx=$wan_tx
        fi
        
        echo
        
        # LAN interface
        if [[ -d "/sys/class/net/$lan_iface" ]]; then
            local lan_rx lan_tx lan_rx_rate lan_tx_rate
            lan_rx=$(cat "/sys/class/net/$lan_iface/statistics/rx_bytes" 2>/dev/null || echo "0")
            lan_tx=$(cat "/sys/class/net/$lan_iface/statistics/tx_bytes" 2>/dev/null || echo "0")
            
            lan_rx_rate=$(( (lan_rx - prev_lan_rx) / 2 / 1024 ))
            lan_tx_rate=$(( (lan_tx - prev_lan_tx) / 2 / 1024 ))
            
            echo "LAN ($lan_iface):"
            echo "  RX: $((lan_rx/1024/1024))MB total, ${lan_rx_rate}KB/s"
            echo "  TX: $((lan_tx/1024/1024))MB total, ${lan_tx_rate}KB/s"
            
            prev_lan_rx=$lan_rx
            prev_lan_tx=$lan_tx
        fi
        
        echo
        
        # Connected clients
        if command -v iw >/dev/null 2>&1 && [[ -d "/sys/class/net/$lan_iface" ]]; then
            local client_count
            client_count=$(iw dev "$lan_iface" station dump 2>/dev/null | grep -c "Station" || echo "0")
            echo "Connected clients: $client_count"
        fi
        
        # Active connections
        local conn_count
        conn_count=$(ss -tuln | wc -l)
        echo "Active connections: $conn_count"
    done
}

run_full_diagnostic() {
    echo "🔧 RPi5 Router - Full Network Diagnostic"
    echo "========================================"
    echo "Generated: $(date)"
    echo "Hostname: $(hostname)"
    echo
    
    check_interfaces
    check_routing
    check_dns
    check_connectivity
    check_firewall
    check_services
    check_wireless
    check_performance
    
    echo "✅ Full diagnostic completed"
    log_diag "Full network diagnostic completed"
}

show_help() {
    cat << EOF
Network Diagnostics Script for RPi5 Secure Router

USAGE:
    $0 {full|interfaces|routing|dns|connectivity|firewall|services|wireless|performance|speed|monitor|help}

COMMANDS:
    full          Run complete network diagnostic
    interfaces    Check network interfaces
    routing       Check routing table and gateway
    dns           Check DNS configuration and resolution
    connectivity  Test internet connectivity
    firewall      Check firewall status
    services      Check network service status
    wireless      Check wireless interface status
    performance   Check system performance
    speed         Run network speed test
    monitor       Real-time traffic monitoring
    help          Show this help message

EXAMPLES:
    $0 full         # Complete diagnostic
    $0 connectivity # Test internet only
    $0 monitor      # Real-time traffic monitor
EOF
}

# Main execution
case "${1:-full}" in
    full)
        run_full_diagnostic
        ;;
    interfaces)
        check_interfaces
        ;;
    routing)
        check_routing
        ;;
    dns)
        check_dns
        ;;
    connectivity)
        check_connectivity
        ;;
    firewall)
        check_firewall
        ;;
    services)
        check_services
        ;;
    wireless)
        check_wireless
        ;;
    performance)
        check_performance
        ;;
    speed)
        run_speed_test
        ;;
    monitor)
        monitor_traffic
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

