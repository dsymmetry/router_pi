#!/bin/bash
#===============================================================================
# MT7612U Adapter Monitoring Script
# Monitors the health and performance of the MT7612U wireless adapter
#===============================================================================

set -euo pipefail

# shellcheck disable=SC2034
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/routerpi"
STATE_DIR="/run/routerpi"
MONITOR_LOG="$LOG_DIR/mt7612u_monitor.log"

# Create directories
mkdir -p "$LOG_DIR" "$STATE_DIR" 2>/dev/null || true

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] MT7612U: $*" | tee -a "$MONITOR_LOG"
}

check_adapter_health() {
    local issues=0
    
    # Check USB connection
    if ! lsusb | grep -q "0e8d:7612"; then
        log "⚠ MT7612U not detected via USB"
        ((issues++))
    fi
    
    # Check driver module
    if ! lsmod | grep -q "mt76x2u"; then
        log "⚠ MT76x2u driver not loaded"
        ((issues++))
    fi
    
    # Check interface existence
    local iface="${1:-wlan0}"
    if [[ ! -d "/sys/class/net/$iface" ]]; then
        log "⚠ Interface $iface not found"
        ((issues++))
    fi
    
    # Check interface status
    if [[ -d "/sys/class/net/$iface" ]]; then
        local operstate
        operstate=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
        if [[ "$operstate" != "up" ]]; then
            log "⚠ Interface $iface is $operstate"
            ((issues++))
        fi
    fi
    
    # Check for error messages in dmesg
    if dmesg | tail -50 | grep -q "mt76\|usb.*disconnect"; then
        log "⚠ Recent adapter errors detected in dmesg"
        ((issues++))
    fi
    
    if [[ $issues -eq 0 ]]; then
        log "✅ Adapter health check passed"
    else
        log "❌ Found $issues adapter issues"
    fi
    
    return $issues
}

get_adapter_stats() {
    local iface="${1:-wlan0}"
    
    if [[ ! -d "/sys/class/net/$iface" ]]; then
        echo "Interface not found"
        return 1
    fi
    
    echo "=== MT7612U Statistics ==="
    echo "Interface: $iface"
    echo "Status: $(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")"
    echo "MAC: $(cat "/sys/class/net/$iface/address" 2>/dev/null || echo "unknown")"
    echo "MTU: $(cat "/sys/class/net/$iface/mtu" 2>/dev/null || echo "unknown")"
    
    # Traffic stats
    local rx_bytes tx_bytes rx_packets tx_packets
    rx_bytes=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo "0")
    tx_bytes=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo "0")
    rx_packets=$(cat "/sys/class/net/$iface/statistics/rx_packets" 2>/dev/null || echo "0")
    tx_packets=$(cat "/sys/class/net/$iface/statistics/tx_packets" 2>/dev/null || echo "0")
    
    echo "RX: $((rx_bytes/1024))KB ($rx_packets packets)"
    echo "TX: $((tx_bytes/1024))KB ($tx_packets packets)"
    
    # Error stats
    local rx_errors tx_errors rx_dropped tx_dropped
    rx_errors=$(cat "/sys/class/net/$iface/statistics/rx_errors" 2>/dev/null || echo "0")
    tx_errors=$(cat "/sys/class/net/$iface/statistics/tx_errors" 2>/dev/null || echo "0")
    rx_dropped=$(cat "/sys/class/net/$iface/statistics/rx_dropped" 2>/dev/null || echo "0")
    tx_dropped=$(cat "/sys/class/net/$iface/statistics/tx_dropped" 2>/dev/null || echo "0")
    
    echo "Errors: RX=$rx_errors TX=$tx_errors"
    echo "Dropped: RX=$rx_dropped TX=$tx_dropped"
    
    # Wireless stats (if available)
    if command -v iw >/dev/null 2>&1; then
        echo
        echo "=== Wireless Information ==="
        iw dev "$iface" info 2>/dev/null || echo "No wireless info available"
        
        echo
        echo "=== Connected Stations ==="
        iw dev "$iface" station dump 2>/dev/null | grep -E "Station|signal|tx bitrate|rx bitrate" || echo "No stations connected"
    fi
}

reset_adapter() {
    log "🔄 Resetting MT7612U adapter..."
    
    # Unload driver
    modprobe -r mt76x2u 2>/dev/null || true
    sleep 2
    
    # Reload driver
    modprobe mt76x2u 2>/dev/null || true
    sleep 3
    
    # Check if reset was successful
    if lsmod | grep -q "mt76x2u"; then
        log "✅ Adapter reset successful"
    else
        log "❌ Adapter reset failed"
        return 1
    fi
}

continuous_monitor() {
    local iface="${1:-wlan0}"
    local interval="${2:-30}"
    
    log "🔍 Starting continuous monitoring of $iface (interval: ${interval}s)"
    
    while true; do
        if ! check_adapter_health "$iface"; then
            log "🚨 Adapter health check failed, attempting reset..."
            reset_adapter
            sleep 10
        fi
        
        # Log basic stats
        if [[ -d "/sys/class/net/$iface" ]]; then
            local rx_bytes tx_bytes
            rx_bytes=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo "0")
            tx_bytes=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo "0")
            log "📊 Traffic: RX=$((rx_bytes/1024))KB TX=$((tx_bytes/1024))KB"
        fi
        
        sleep "$interval"
    done
}

show_help() {
    cat << EOF
MT7612U Adapter Monitoring Script

USAGE:
    $0 {check|stats|reset|monitor|help} [interface]

COMMANDS:
    check      Check adapter health
    stats      Show detailed adapter statistics
    reset      Reset the MT7612U adapter
    monitor    Start continuous monitoring (30s interval)
    help       Show this help message

EXAMPLES:
    $0 check wlan0
    $0 stats wlan1
    $0 monitor wlan0
EOF
}

# Main execution
case "${1:-help}" in
    check)
        check_adapter_health "${2:-wlan0}"
        ;;
    stats)
        get_adapter_stats "${2:-wlan0}"
        ;;
    reset)
        reset_adapter
        ;;
    monitor)
        continuous_monitor "${2:-wlan0}"
        ;;
    start)
        # For compatibility with main router script
        continuous_monitor "${2:-wlan0}" &
        echo $! > "$STATE_DIR/mt7612u_monitor.pid"
        ;;
    stop)
        if [[ -f "$STATE_DIR/mt7612u_monitor.pid" ]]; then
            kill "$(cat "$STATE_DIR/mt7612u_monitor.pid")" 2>/dev/null || true
            rm -f "$STATE_DIR/mt7612u_monitor.pid"
        fi
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

