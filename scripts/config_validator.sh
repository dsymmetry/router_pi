#!/bin/bash
#===============================================================================
# Configuration Validator for RPi5 Secure Router
# Validates system configuration and security settings
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/routerpi"
VALIDATION_LOG="$LOG_DIR/config_validation.log"

# Create directories
mkdir -p "$LOG_DIR" 2>/dev/null || true

log_validation() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] VALIDATION: $*" | tee -a "$VALIDATION_LOG"
}

validate_interfaces() {
    local issues=0
    
    echo "🌐 Interface Configuration Validation"
    echo "===================================="
    
    # Check WAN interface
    local wan_iface="${WAN_IFACE:-$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')}"
    if [[ -n "$wan_iface" ]] && [[ -d "/sys/class/net/$wan_iface" ]]; then
        echo "✅ WAN interface ($wan_iface) exists"
        
        # Check if interface has IP
        if ip addr show "$wan_iface" | grep -q "inet "; then
            echo "✅ WAN interface has IP address"
        else
            echo "⚠️ WAN interface has no IP address"
            ((issues++))
        fi
    else
        echo "❌ WAN interface not found or invalid"
        ((issues++))
    fi
    
    # Check LAN interface
    local lan_iface="${LAN_IFACE:-wlan0}"
    if [[ -d "/sys/class/net/$lan_iface" ]]; then
        echo "✅ LAN interface ($lan_iface) exists"
        
        # Check if MT7612U
        if lsusb | grep -q "0e8d:7612"; then
            echo "✅ MT7612U adapter detected"
        else
            echo "⚠️ MT7612U adapter not detected"
            ((issues++))
        fi
    else
        echo "❌ LAN interface ($lan_iface) not found"
        ((issues++))
    fi
    
    echo
    return $issues
}

validate_hostapd_config() {
    local issues=0
    local config_file="${HOSTAPD_CONF:-/etc/hostapd/hostapd.conf}"
    
    echo "📡 Hostapd Configuration Validation"
    echo "=================================="
    
    if [[ -f "$config_file" ]]; then
        echo "✅ Hostapd configuration exists: $config_file"
        
        # Check essential settings
        local checks=(
            "interface:Interface setting"
            "ssid:SSID setting"
            "wpa=2:WPA2 encryption"
            "wpa_passphrase:WiFi password"
            "ap_isolate=1:AP isolation"
        )
        
        for check in "${checks[@]}"; do
            local setting="${check%:*}"
            local description="${check#*:}"
            
            if grep -q "^$setting" "$config_file"; then
                echo "✅ $description configured"
            else
                echo "⚠️ $description missing or commented"
                ((issues++))
            fi
        done
        
        # Check password strength
        if [[ -f "/run/routerpi/wifi_password" ]]; then
            local password
            password=$(cat "/run/routerpi/wifi_password")
            local length=${#password}
            
            if [[ $length -ge 20 ]]; then
                echo "✅ WiFi password is strong ($length characters)"
            elif [[ $length -ge 12 ]]; then
                echo "⚠️ WiFi password is moderate ($length characters)"
                ((issues++))
            else
                echo "❌ WiFi password is weak ($length characters)"
                ((issues++))
            fi
        fi
        
        # Validate configuration syntax
        if hostapd -t "$config_file" >/dev/null 2>&1; then
            echo "✅ Hostapd configuration syntax is valid"
        else
            echo "❌ Hostapd configuration has syntax errors"
            ((issues++))
        fi
        
    else
        echo "❌ Hostapd configuration not found: $config_file"
        ((issues++))
    fi
    
    echo
    return $issues
}

validate_dnsmasq_config() {
    local issues=0
    local config_file="/etc/dnsmasq.d/router-secure.conf"
    
    echo "🔍 DNSmasq Configuration Validation"
    echo "=================================="
    
    if [[ -f "$config_file" ]]; then
        echo "✅ DNSmasq configuration exists: $config_file"
        
        # Check essential settings
        local checks=(
            "interface=:Interface binding"
            "bind-interfaces:Interface binding mode"
            "dhcp-range=:DHCP range"
            "stop-dns-rebind:DNS rebinding protection"
            "bogus-priv:Private reverse lookup protection"
        )
        
        for check in "${checks[@]}"; do
            local setting="${check%:*}"
            local description="${check#*:}"
            
            if grep -q "^$setting" "$config_file"; then
                echo "✅ $description configured"
            else
                echo "⚠️ $description missing"
                ((issues++))
            fi
        done
        
        # Check DNS servers
        if grep -q "^server=" "$config_file"; then
            echo "✅ Upstream DNS servers configured"
            local dns_count
            dns_count=$(grep -c "^server=" "$config_file")
            echo "  DNS servers configured: $dns_count"
        else
            echo "❌ No upstream DNS servers configured"
            ((issues++))
        fi
        
        # Validate configuration syntax
        if dnsmasq --test --conf-file="$config_file" >/dev/null 2>&1; then
            echo "✅ DNSmasq configuration syntax is valid"
        else
            echo "❌ DNSmasq configuration has syntax errors"
            ((issues++))
        fi
        
    else
        echo "❌ DNSmasq configuration not found: $config_file"
        ((issues++))
    fi
    
    echo
    return $issues
}

validate_firewall_config() {
    local issues=0
    
    echo "🛡️ Firewall Configuration Validation"
    echo "==================================="
    
    if ! command -v iptables >/dev/null 2>&1; then
        echo "❌ iptables not found"
        ((issues++))
        return $issues
    fi
    
    # Check default policies
    local input_policy forward_policy
    input_policy=$(iptables -L INPUT | head -1 | awk '{print $4}' | tr -d '()')
    forward_policy=$(iptables -L FORWARD | head -1 | awk '{print $4}' | tr -d '()')
    
    if [[ "$input_policy" == "DROP" ]]; then
        echo "✅ INPUT policy is DROP (secure)"
    else
        echo "❌ INPUT policy is $input_policy (should be DROP)"
        ((issues++))
    fi
    
    if [[ "$forward_policy" == "DROP" ]]; then
        echo "✅ FORWARD policy is DROP (secure)"
    else
        echo "❌ FORWARD policy is $forward_policy (should be DROP)"
        ((issues++))
    fi
    
    # Check essential rules
    local rule_checks=(
        "INPUT.*ACCEPT.*lo:Loopback allowed"
        "INPUT.*ESTABLISHED,RELATED:Established connections"
        "POSTROUTING.*MASQUERADE:NAT masquerading"
    )
    
    for check in "${rule_checks[@]}"; do
        local pattern="${check%:*}"
        local description="${check#*:}"
        
        if iptables -L -t filter -n | grep -q "$pattern" || iptables -L -t nat -n | grep -q "$pattern"; then
            echo "✅ $description configured"
        else
            echo "⚠️ $description missing"
            ((issues++))
        fi
    done
    
    # Check for security rules
    if iptables -L | grep -q "limit"; then
        echo "✅ Rate limiting rules found"
    else
        echo "⚠️ No rate limiting rules detected"
        ((issues++))
    fi
    
    if iptables -L | grep -q "connlimit"; then
        echo "✅ Connection limiting rules found"
    else
        echo "⚠️ No connection limiting rules detected"
        ((issues++))
    fi
    
    echo
    return $issues
}

validate_system_hardening() {
    local issues=0
    
    echo "🔒 System Hardening Validation"
    echo "============================="
    
    # Check sysctl security settings
    local sysctl_file="/etc/sysctl.d/99-router-security.conf"
    if [[ -f "$sysctl_file" ]]; then
        echo "✅ Security sysctl configuration exists"
        
        # Check critical settings
        local settings=(
            "net.ipv4.ip_forward=1:IP forwarding"
            "net.ipv6.conf.all.disable_ipv6=1:IPv6 disabled"
            "net.ipv4.conf.all.send_redirects=0:ICMP redirects disabled"
            "net.ipv4.tcp_syncookies=1:SYN cookies enabled"
            "kernel.dmesg_restrict=1:Kernel log protection"
        )
        
        for setting_desc in "${settings[@]}"; do
            local setting="${setting_desc%:*}"
            local description="${setting_desc#*:}"
            
            if grep -q "^$setting" "$sysctl_file"; then
                echo "✅ $description"
            else
                echo "⚠️ Missing: $description"
                ((issues++))
            fi
        done
    else
        echo "❌ Security sysctl configuration not found"
        ((issues++))
    fi
    
    # Check file permissions
    local file_checks=(
        "/etc/hostapd/hostapd.conf:600:Hostapd config permissions"
        "/run/routerpi/wifi_password:600:WiFi password permissions"
    )
    
    for file_check in "${file_checks[@]}"; do
        local file="${file_check%%:*}"
        local temp="${file_check#*:}"
        local expected_perm="${temp%:*}"
        local description="${temp#*:}"
        
        if [[ -f "$file" ]]; then
            local actual_perm
            actual_perm=$(stat -c %a "$file" 2>/dev/null)
            if [[ "$actual_perm" == "$expected_perm" ]]; then
                echo "✅ $description ($actual_perm)"
            else
                echo "⚠️ $description ($actual_perm, should be $expected_perm)"
                ((issues++))
            fi
        fi
    done
    
    # Check running services
    local unwanted_services=("bluetooth" "cups" "avahi-daemon")
    
    for service in "${unwanted_services[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            echo "⚠️ Unnecessary service enabled: $service"
            ((issues++))
        else
            echo "✅ Unnecessary service disabled: $service"
        fi
    done
    
    echo
    return $issues
}

validate_logging_config() {
    local issues=0
    
    echo "📊 Logging Configuration Validation"
    echo "=================================="
    
    # Check log directories
    if [[ -d "/var/log/routerpi" ]]; then
        echo "✅ Router log directory exists"
        
        # Check permissions
        local log_perms
        log_perms=$(stat -c %a "/var/log/routerpi" 2>/dev/null)
        if [[ "$log_perms" == "755" ]]; then
            echo "✅ Log directory permissions correct ($log_perms)"
        else
            echo "⚠️ Log directory permissions ($log_perms, should be 755)"
            ((issues++))
        fi
    else
        echo "❌ Router log directory missing"
        ((issues++))
    fi
    
    # Check logrotate configuration
    if [[ -f "/etc/logrotate.d/routerpi" ]]; then
        echo "✅ Log rotation configured"
    else
        echo "⚠️ Log rotation not configured"
        ((issues++))
    fi
    
    # Check log files (if they exist)
    local log_files=("router.log" "security.log" "traffic.log")
    for log_file in "${log_files[@]}"; do
        if [[ -f "/var/log/routerpi/$log_file" ]]; then
            echo "✅ $log_file exists"
        else
            echo "ℹ️ $log_file not created yet"
        fi
    done
    
    echo
    return $issues
}

validate_vpn_support() {
    local issues=0
    
    echo "🔐 VPN Support Validation"
    echo "========================"
    
    # Check WireGuard
    if command -v wg >/dev/null 2>&1; then
        echo "✅ WireGuard client available"
        
        if lsmod | grep -q "^wireguard"; then
            echo "✅ WireGuard kernel module loaded"
        elif modinfo wireguard >/dev/null 2>&1; then
            echo "⚠️ WireGuard module available but not loaded"
            ((issues++))
        else
            echo "❌ WireGuard kernel module not available"
            ((issues++))
        fi
    else
        echo "⚠️ WireGuard not installed"
        ((issues++))
    fi
    
    # Check OpenVPN
    if command -v openvpn >/dev/null 2>&1; then
        echo "✅ OpenVPN client available"
    else
        echo "⚠️ OpenVPN not installed"
        ((issues++))
    fi
    
    # Check TUN/TAP
    if lsmod | grep -q "^tun"; then
        echo "✅ TUN/TAP module loaded"
    else
        echo "⚠️ TUN/TAP module not loaded"
        ((issues++))
    fi
    
    echo
    return $issues
}

run_full_validation() {
    local total_issues=0
    
    echo "🔍 RPi5 Secure Router - Configuration Validation"
    echo "==============================================="
    echo "Started: $(date)"
    echo "Hostname: $(hostname)"
    echo
    
    # Run all validation checks
    validate_interfaces
    total_issues=$((total_issues + $?))
    
    validate_hostapd_config
    total_issues=$((total_issues + $?))
    
    validate_dnsmasq_config
    total_issues=$((total_issues + $?))
    
    validate_firewall_config
    total_issues=$((total_issues + $?))
    
    validate_system_hardening
    total_issues=$((total_issues + $?))
    
    validate_logging_config
    total_issues=$((total_issues + $?))
    
    validate_vpn_support
    total_issues=$((total_issues + $?))
    
    # Summary
    echo "📋 Validation Summary"
    echo "===================="
    
    if [[ $total_issues -eq 0 ]]; then
        echo "🎉 Excellent! Configuration validation passed."
        echo "   All systems are properly configured."
    elif [[ $total_issues -le 5 ]]; then
        echo "✅ Good configuration with $total_issues minor issues."
        echo "   Consider addressing the warnings above."
    elif [[ $total_issues -le 10 ]]; then
        echo "⚠️ Configuration needs attention - $total_issues issues found."
        echo "   Please address the issues above."
    else
        echo "❌ Configuration has significant issues - $total_issues problems found."
        echo "   Please address all critical issues before deployment."
    fi
    
    echo
    echo "💡 Recommendations:"
    echo "   - Run './router_pi_secure.sh audit' for security assessment"
    echo "   - Check './scripts/network_diag.sh full' for network diagnostics"
    echo "   - Review configuration files for any missing settings"
    echo "   - Ensure all required packages are installed"
    
    log_validation "Configuration validation completed - $total_issues issues found"
    return $total_issues
}

show_help() {
    cat << EOF
Configuration Validator for RPi5 Secure Router

USAGE:
    $0 {full|interfaces|hostapd|dnsmasq|firewall|system|logging|vpn|help}

COMMANDS:
    full       Run complete configuration validation
    interfaces Check network interface configuration
    hostapd    Validate hostapd configuration
    dnsmasq    Validate DNSmasq configuration
    firewall   Check firewall configuration
    system     Validate system hardening
    logging    Check logging configuration
    vpn        Validate VPN support
    help       Show this help message

EXAMPLES:
    $0 full      # Complete validation
    $0 hostapd   # Check WiFi configuration only
    $0 firewall  # Check firewall rules only
EOF
}

# Main execution
case "${1:-full}" in
    full)
        run_full_validation
        ;;
    interfaces)
        validate_interfaces
        ;;
    hostapd)
        validate_hostapd_config
        ;;
    dnsmasq)
        validate_dnsmasq_config
        ;;
    firewall)
        validate_firewall_config
        ;;
    system)
        validate_system_hardening
        ;;
    logging)
        validate_logging_config
        ;;
    vpn)
        validate_vpn_support
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
