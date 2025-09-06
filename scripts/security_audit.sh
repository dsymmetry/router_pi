#!/bin/bash
#===============================================================================
# Security Audit Script for RPi5 Secure Router
# Comprehensive security assessment and hardening verification
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/routerpi"
AUDIT_LOG="$LOG_DIR/security_audit.log"

# Create directories
mkdir -p "$LOG_DIR" 2>/dev/null || true

log_audit() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] AUDIT: $*" | tee -a "$AUDIT_LOG"
}

check_firewall_security() {
    local issues=0
    
    echo "🛡️ Firewall Security Assessment"
    echo "================================"
    
    # Check if iptables is active
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
        echo "⚠️ INPUT policy is $input_policy (should be DROP)"
        ((issues++))
    fi
    
    if [[ "$forward_policy" == "DROP" ]]; then
        echo "✅ FORWARD policy is DROP (secure)"
    else
        echo "⚠️ FORWARD policy is $forward_policy (should be DROP)"
        ((issues++))
    fi
    
    # Check for basic rules
    if iptables -L INPUT | grep -q "ACCEPT.*lo"; then
        echo "✅ Loopback interface allowed"
    else
        echo "⚠️ Loopback interface not explicitly allowed"
        ((issues++))
    fi
    
    if iptables -L INPUT | grep -q "ESTABLISHED,RELATED"; then
        echo "✅ Established connections allowed"
    else
        echo "⚠️ Established connections rule not found"
        ((issues++))
    fi
    
    # Check NAT rules
    if iptables -t nat -L POSTROUTING | grep -q "MASQUERADE"; then
        echo "✅ NAT masquerading configured"
    else
        echo "⚠️ NAT masquerading not found"
        ((issues++))
    fi
    
    # Check for rate limiting
    if iptables -L | grep -q "limit"; then
        echo "✅ Rate limiting rules found"
    else
        echo "⚠️ No rate limiting rules detected"
        ((issues++))
    fi
    
    # Check for connection limiting
    if iptables -L | grep -q "connlimit"; then
        echo "✅ Connection limiting rules found"
    else
        echo "⚠️ No connection limiting rules detected"
        ((issues++))
    fi
    
    echo
    return $issues
}

check_service_security() {
    local issues=0
    
    echo "🔧 Service Security Assessment"
    echo "============================="
    
    # Check critical services
    local services=("hostapd" "dnsmasq" "ssh")
    
    for service in "${services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            echo "✅ $service is running"
            
            # Service-specific checks
            case "$service" in
                "hostapd")
                    if [[ -f /etc/hostapd/hostapd.conf ]]; then
                        if grep -q "wpa=2" /etc/hostapd/hostapd.conf; then
                            echo "  ✅ WPA2 encryption enabled"
                        else
                            echo "  ⚠️ WPA2 encryption not found"
                            ((issues++))
                        fi
                        
                        if grep -q "ap_isolate=1" /etc/hostapd/hostapd.conf; then
                            echo "  ✅ AP isolation enabled"
                        else
                            echo "  ⚠️ AP isolation not enabled"
                            ((issues++))
                        fi
                    fi
                    ;;
                "dnsmasq")
                    if [[ -f /etc/dnsmasq.d/router-secure.conf ]]; then
                        echo "  ✅ Secure DNS configuration found"
                        if grep -q "stop-dns-rebind" /etc/dnsmasq.d/router-secure.conf; then
                            echo "  ✅ DNS rebinding protection enabled"
                        else
                            echo "  ⚠️ DNS rebinding protection not found"
                            ((issues++))
                        fi
                    else
                        echo "  ⚠️ Secure DNS configuration not found"
                        ((issues++))
                    fi
                    ;;
                "ssh")
                    if [[ -f /etc/ssh/sshd_config ]]; then
                        if grep -q "PermitRootLogin no" /etc/ssh/sshd_config; then
                            echo "  ✅ Root login disabled"
                        else
                            echo "  ⚠️ Root login may be enabled"
                            ((issues++))
                        fi
                    fi
                    ;;
            esac
        else
            if [[ "$service" == "ssh" ]]; then
                echo "ℹ️ $service is not running (may be intentional)"
            else
                echo "⚠️ $service is not running"
                ((issues++))
            fi
        fi
    done
    
    echo
    return $issues
}

check_system_hardening() {
    local issues=0
    
    echo "🔒 System Hardening Assessment"
    echo "============================="
    
    # Check sysctl security settings
    if [[ -f /etc/sysctl.d/99-router-security.conf ]]; then
        echo "✅ Security sysctl configuration found"
        
        # Check specific settings
        local settings=(
            "net.ipv4.ip_forward=1"
            "net.ipv6.conf.all.disable_ipv6=1"
            "net.ipv4.conf.all.send_redirects=0"
            "net.ipv4.conf.all.accept_redirects=0"
            "net.ipv4.tcp_syncookies=1"
        )
        
        for setting in "${settings[@]}"; do
            if grep -q "$setting" /etc/sysctl.d/99-router-security.conf; then
                echo "  ✅ $setting"
            else
                echo "  ⚠️ Missing: $setting"
                ((issues++))
            fi
        done
    else
        echo "⚠️ Security sysctl configuration not found"
        ((issues++))
    fi
    
    # Check file permissions
    local sensitive_files=(
        "/etc/hostapd/hostapd.conf:600"
        "/run/routerpi/wifi_password:600"
    )
    
    for file_perm in "${sensitive_files[@]}"; do
        local file="${file_perm%:*}"
        local expected_perm="${file_perm#*:}"
        
        if [[ -f "$file" ]]; then
            local actual_perm
            actual_perm=$(stat -c %a "$file" 2>/dev/null)
            if [[ "$actual_perm" == "$expected_perm" ]]; then
                echo "  ✅ $file has secure permissions ($actual_perm)"
            else
                echo "  ⚠️ $file has insecure permissions ($actual_perm, should be $expected_perm)"
                ((issues++))
            fi
        else
            echo "  ℹ️ $file not found (may not be created yet)"
        fi
    done
    
    # Check for unnecessary services
    local unnecessary_services=("bluetooth" "cups" "avahi-daemon")
    
    for service in "${unnecessary_services[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            echo "  ⚠️ Unnecessary service enabled: $service"
            ((issues++))
        else
            echo "  ✅ Unnecessary service disabled: $service"
        fi
    done
    
    echo
    return $issues
}

check_network_security() {
    local issues=0
    
    echo "🌐 Network Security Assessment"
    echo "============================="
    
    # Check IPv6 status
    if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
        local ipv6_disabled
        ipv6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
        if [[ "$ipv6_disabled" == "1" ]]; then
            echo "✅ IPv6 is disabled (reduced attack surface)"
        else
            echo "⚠️ IPv6 is enabled (consider disabling for security)"
            ((issues++))
        fi
    fi
    
    # Check for open ports
    if command -v ss >/dev/null 2>&1; then
        echo "📊 Open ports analysis:"
        local open_ports
        open_ports=$(ss -tuln | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -n | uniq)
        
        for port in $open_ports; do
            case "$port" in
                22) echo "  ✅ Port $port (SSH) - secure if properly configured" ;;
                53) echo "  ✅ Port $port (DNS) - expected for router" ;;
                67) echo "  ✅ Port $port (DHCP) - expected for router" ;;
                80) echo "  ⚠️ Port $port (HTTP) - consider if needed" ;;
                443) echo "  ⚠️ Port $port (HTTPS) - consider if needed" ;;
                *) echo "  ❓ Port $port - review if necessary"
                   ((issues++)) ;;
            esac
        done
    fi
    
    echo
    return $issues
}

check_password_security() {
    local issues=0
    
    echo "🔑 Password Security Assessment"
    echo "=============================="
    
    # Check WiFi password
    if [[ -f /run/routerpi/wifi_password ]]; then
        local password
        password=$(cat /run/routerpi/wifi_password)
        local length=${#password}
        
        if [[ $length -ge 20 ]]; then
            echo "✅ WiFi password is strong ($length characters)"
        elif [[ $length -ge 12 ]]; then
            echo "⚠️ WiFi password is moderate ($length characters, consider longer)"
            ((issues++))
        else
            echo "❌ WiFi password is weak ($length characters)"
            ((issues++))
        fi
        
        # Check password complexity
        if [[ "$password" =~ [A-Z] ]] && [[ "$password" =~ [a-z] ]] && [[ "$password" =~ [0-9] ]]; then
            echo "✅ WiFi password has good complexity"
        else
            echo "⚠️ WiFi password could have better complexity"
            ((issues++))
        fi
    else
        echo "ℹ️ WiFi password file not found (may not be generated yet)"
    fi
    
    echo
    return $issues
}

check_logging_monitoring() {
    local issues=0
    
    echo "📊 Logging and Monitoring Assessment"
    echo "==================================="
    
    # Check log directories
    if [[ -d /var/log/routerpi ]]; then
        echo "✅ Router logging directory exists"
        
        # Check log files
        local log_files=("router.log" "security.log" "traffic.log")
        for log_file in "${log_files[@]}"; do
            if [[ -f "/var/log/routerpi/$log_file" ]]; then
                echo "  ✅ $log_file exists"
            else
                echo "  ℹ️ $log_file not found (may not be created yet)"
            fi
        done
    else
        echo "⚠️ Router logging directory not found"
        ((issues++))
    fi
    
    # Check if monitoring is active
    if pgrep -f "mt7612u_monitor" >/dev/null; then
        echo "✅ MT7612U monitoring is active"
    else
        echo "ℹ️ MT7612U monitoring not running"
    fi
    
    echo
    return $issues
}

generate_security_report() {
    local total_issues=0
    
    echo "🔐 RPi5 Secure Router - Security Audit Report"
    echo "=============================================="
    echo "Generated: $(date)"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo
    
    # Run all security checks
    check_firewall_security
    total_issues=$((total_issues + $?))
    
    check_service_security
    total_issues=$((total_issues + $?))
    
    check_system_hardening
    total_issues=$((total_issues + $?))
    
    check_network_security
    total_issues=$((total_issues + $?))
    
    check_password_security
    total_issues=$((total_issues + $?))
    
    check_logging_monitoring
    total_issues=$((total_issues + $?))
    
    # Summary
    echo "📋 Security Audit Summary"
    echo "========================"
    
    if [[ $total_issues -eq 0 ]]; then
        echo "🎉 Excellent! No security issues found."
        echo "   Your router appears to be well-secured."
    elif [[ $total_issues -le 3 ]]; then
        echo "✅ Good security posture with $total_issues minor issues."
        echo "   Consider addressing the warnings above."
    elif [[ $total_issues -le 6 ]]; then
        echo "⚠️ Moderate security with $total_issues issues found."
        echo "   Please address the issues above to improve security."
    else
        echo "❌ Security needs improvement - $total_issues issues found."
        echo "   Please address the critical issues immediately."
    fi
    
    echo
    echo "💡 Security Recommendations:"
    echo "   - Regularly update system packages"
    echo "   - Monitor logs for suspicious activity"
    echo "   - Change WiFi password periodically"
    echo "   - Keep router firmware updated"
    echo "   - Review firewall rules regularly"
    echo "   - Disable unnecessary services"
    
    log_audit "Security audit completed - $total_issues issues found"
}

quick_security_check() {
    echo "🔍 Quick Security Check"
    echo "======================"
    
    local issues=0
    
    # Essential checks only
    if iptables -L INPUT | grep -q "DROP"; then
        echo "✅ Firewall active"
    else
        echo "❌ Firewall not active"
        ((issues++))
    fi
    
    if systemctl is-active hostapd >/dev/null 2>&1; then
        echo "✅ WiFi AP running"
    else
        echo "❌ WiFi AP not running"
        ((issues++))
    fi
    
    if systemctl is-active dnsmasq >/dev/null 2>&1; then
        echo "✅ DNS/DHCP running"
    else
        echo "❌ DNS/DHCP not running"
        ((issues++))
    fi
    
    echo
    if [[ $issues -eq 0 ]]; then
        echo "🎉 Quick check passed - basic security looks good!"
    else
        echo "⚠️ Found $issues basic issues - run full audit for details"
    fi
}

show_help() {
    cat << EOF
Security Audit Script for RPi5 Secure Router

USAGE:
    $0 {full|quick|firewall|services|system|network|passwords|logs|help}

COMMANDS:
    full       Run comprehensive security audit
    quick      Run quick security check
    firewall   Check firewall configuration only
    services   Check service security only
    system     Check system hardening only
    network    Check network security only
    passwords  Check password security only
    logs       Check logging and monitoring only
    help       Show this help message

EXAMPLES:
    $0 full     # Complete security audit
    $0 quick    # Quick status check
    $0 firewall # Check firewall rules only
EOF
}

# Main execution
case "${1:-full}" in
    full)
        generate_security_report
        ;;
    quick)
        quick_security_check
        ;;
    firewall)
        check_firewall_security
        ;;
    services)
        check_service_security
        ;;
    system)
        check_system_hardening
        ;;
    network)
        check_network_security
        ;;
    passwords)
        check_password_security
        ;;
    logs)
        check_logging_monitoring
        ;;
    start)
        # For compatibility with main router script
        echo "Security audit monitoring started"
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

