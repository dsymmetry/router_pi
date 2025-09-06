#!/bin/bash
#===============================================================================
# Advanced Firewall Rules for RPi5 Secure Router
# Comprehensive iptables configuration with security hardening
#===============================================================================

set -euo pipefail

# Get interfaces from environment or detect
WAN_IFACE="${WAN_IFACE:-$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')}"
LAN_IFACE="${LAN_IFACE:-wlan0}"
AP_SUBNET="${AP_ADDR:-192.168.8.0/24}"

# Security settings
MAX_CONN_PER_IP="${MAX_CONN_PER_IP:-20}"
RATE_LIMIT="${RATE_LIMIT:-50/sec}"
BURST_LIMIT="${BURST_LIMIT:-20}"
SSH_RATE_LIMIT="${SSH_RATE_LIMIT:-4}"
SCAN_THRESHOLD="${SCAN_THRESHOLD:-10}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] FIREWALL: $*"
}

flush_rules() {
    log "Flushing existing iptables rules..."
    
    # Flush all chains
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -t raw -F
    iptables -t raw -X
    
    # Reset counters
    iptables -Z
    iptables -t nat -Z
    iptables -t mangle -Z
}

set_default_policies() {
    log "Setting default policies..."
    
    # Default policies - DROP for security
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
}

create_custom_chains() {
    log "Creating custom chains..."
    
    # Anti-DDoS chains
    iptables -N DDOS_PROTECTION
    iptables -N RATE_LIMIT
    iptables -N CONN_LIMIT
    
    # Security chains
    iptables -N PORT_SCAN
    iptables -N INVALID_PACKETS
    iptables -N SSH_PROTECTION
    
    # Logging chains
    iptables -N LOG_DROP
    iptables -N LOG_ACCEPT
}

setup_anti_ddos() {
    log "Setting up anti-DDoS protection..."
    
    # DDOS_PROTECTION chain
    iptables -A DDOS_PROTECTION -m limit --limit 1/s --limit-burst 4 -j RETURN
    iptables -A DDOS_PROTECTION -j LOG --log-prefix "DDOS-ATTACK: " --log-level 4
    iptables -A DDOS_PROTECTION -j DROP
    
    # RATE_LIMIT chain
    iptables -A RATE_LIMIT -m hashlimit \
        --hashlimit-above "$RATE_LIMIT" \
        --hashlimit-burst "$BURST_LIMIT" \
        --hashlimit-mode srcip \
        --hashlimit-name conn_rate_limit \
        --hashlimit-htable-expire 300000 \
        -j LOG --log-prefix "RATE-LIMIT: " --log-level 4
    iptables -A RATE_LIMIT -m hashlimit \
        --hashlimit-above "$RATE_LIMIT" \
        --hashlimit-burst "$BURST_LIMIT" \
        --hashlimit-mode srcip \
        --hashlimit-name conn_rate_limit \
        --hashlimit-htable-expire 300000 \
        -j DROP
    iptables -A RATE_LIMIT -j RETURN
    
    # CONN_LIMIT chain
    iptables -A CONN_LIMIT -p tcp --syn -m connlimit \
        --connlimit-above "$MAX_CONN_PER_IP" \
        --connlimit-mask 32 \
        -j LOG --log-prefix "CONN-LIMIT: " --log-level 4
    iptables -A CONN_LIMIT -p tcp --syn -m connlimit \
        --connlimit-above "$MAX_CONN_PER_IP" \
        --connlimit-mask 32 \
        -j REJECT --reject-with tcp-reset
    iptables -A CONN_LIMIT -j RETURN
}

setup_port_scan_detection() {
    log "Setting up port scan detection..."
    
    # PORT_SCAN chain
    # Detect TCP port scans
    iptables -A PORT_SCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
    iptables -A PORT_SCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m recent --name portscan --set -j LOG --log-prefix "PORTSCAN-DETECTED: " --log-level 4
    iptables -A PORT_SCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j DROP
    
    # Detect stealth scans
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "STEALTH-SCAN: " --log-level 4
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL NONE -j DROP
    
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "XMAS-SCAN: " --log-level 4
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL ALL -j DROP
    
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL FIN,PSH,URG -j LOG --log-prefix "NULL-SCAN: " --log-level 4
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
    
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL SYN,FIN -j LOG --log-prefix "SYN-FIN-SCAN: " --log-level 4
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL SYN,FIN -j DROP
    
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL SYN,RST -j LOG --log-prefix "SYN-RST-SCAN: " --log-level 4
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL SYN,RST -j DROP
    
    iptables -A PORT_SCAN -j RETURN
}

setup_invalid_packet_protection() {
    log "Setting up invalid packet protection..."
    
    # INVALID_PACKETS chain
    iptables -A INVALID_PACKETS -m state --state INVALID -j LOG --log-prefix "INVALID-PACKET: " --log-level 4
    iptables -A INVALID_PACKETS -m state --state INVALID -j DROP
    
    # TCP flag combinations that should never occur
    iptables -A INVALID_PACKETS -p tcp --tcp-flags FIN,RST FIN,RST -j LOG --log-prefix "INVALID-TCP: " --log-level 4
    iptables -A INVALID_PACKETS -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
    
    iptables -A INVALID_PACKETS -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG --log-prefix "INVALID-TCP: " --log-level 4
    iptables -A INVALID_PACKETS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    
    # Fragmented packets
    iptables -A INVALID_PACKETS -f -j LOG --log-prefix "FRAGMENT: " --log-level 4
    iptables -A INVALID_PACKETS -f -j DROP
    
    iptables -A INVALID_PACKETS -j RETURN
}

setup_ssh_protection() {
    log "Setting up SSH protection..."
    
    # SSH_PROTECTION chain
    # Rate limit SSH connections
    iptables -A SSH_PROTECTION -p tcp --dport 22 -m state --state NEW -m recent --name ssh --set
    iptables -A SSH_PROTECTION -p tcp --dport 22 -m state --state NEW -m recent --name ssh --update --seconds 60 --hitcount "$SSH_RATE_LIMIT" -j LOG --log-prefix "SSH-BRUTE-FORCE: " --log-level 4
    iptables -A SSH_PROTECTION -p tcp --dport 22 -m state --state NEW -m recent --name ssh --update --seconds 60 --hitcount "$SSH_RATE_LIMIT" -j DROP
    
    # Allow SSH from LAN only
    iptables -A SSH_PROTECTION -i "$LAN_IFACE" -p tcp --dport 22 -j ACCEPT
    
    # Drop SSH from WAN
    iptables -A SSH_PROTECTION -i "$WAN_IFACE" -p tcp --dport 22 -j LOG --log-prefix "SSH-WAN-BLOCKED: " --log-level 4
    iptables -A SSH_PROTECTION -i "$WAN_IFACE" -p tcp --dport 22 -j DROP
    
    iptables -A SSH_PROTECTION -j RETURN
}

setup_logging_chains() {
    log "Setting up logging chains..."
    
    # LOG_DROP chain
    iptables -A LOG_DROP -m limit --limit 5/min -j LOG --log-prefix "DROPPED: " --log-level 4
    iptables -A LOG_DROP -j DROP
    
    # LOG_ACCEPT chain  
    iptables -A LOG_ACCEPT -m limit --limit 10/min -j LOG --log-prefix "ACCEPTED: " --log-level 4
    iptables -A LOG_ACCEPT -j ACCEPT
}

setup_input_rules() {
    log "Setting up INPUT chain rules..."
    
    # Apply security checks first
    iptables -A INPUT -j INVALID_PACKETS
    iptables -A INPUT -j PORT_SCAN
    iptables -A INPUT -j RATE_LIMIT
    
    # Loopback interface
    iptables -A INPUT -i lo -j ACCEPT
    
    # Allow established and related connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # ICMP (ping) - rate limited
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 2 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-prefix "ICMP-FLOOD: " --log-level 4
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    
    # Allow other essential ICMP types
    iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT
    
    # SSH protection
    iptables -A INPUT -p tcp --dport 22 -j SSH_PROTECTION
    
    # DNS for clients (from LAN only)
    iptables -A INPUT -i "$LAN_IFACE" -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$LAN_IFACE" -p tcp --dport 53 -j ACCEPT
    
    # DHCP for clients (from LAN only)
    iptables -A INPUT -i "$LAN_IFACE" -p udp --dport 67 -j ACCEPT
    
    # HTTP/HTTPS for captive portal or management (from LAN only)
    iptables -A INPUT -i "$LAN_IFACE" -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -i "$LAN_IFACE" -p tcp --dport 443 -j ACCEPT
    
    # Block common attack ports
    local attack_ports=(135 137 138 139 445 593 1024 1433 3389 5900)
    for port in "${attack_ports[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j LOG --log-prefix "ATTACK-PORT-$port: " --log-level 4
        iptables -A INPUT -p tcp --dport "$port" -j DROP
        iptables -A INPUT -p udp --dport "$port" -j LOG --log-prefix "ATTACK-PORT-$port: " --log-level 4
        iptables -A INPUT -p udp --dport "$port" -j DROP
    done
    
    # Log and drop everything else
    iptables -A INPUT -j LOG_DROP
}

setup_forward_rules() {
    log "Setting up FORWARD chain rules..."
    
    # Apply security checks
    iptables -A FORWARD -j INVALID_PACKETS
    iptables -A FORWARD -j RATE_LIMIT
    iptables -A FORWARD -j CONN_LIMIT
    
    # Allow established and related connections
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # SYN flood protection
    iptables -A FORWARD -p tcp --syn -m limit --limit 2/s --limit-burst 6 -j ACCEPT
    iptables -A FORWARD -p tcp --syn -j LOG --log-prefix "SYN-FLOOD: " --log-level 4
    iptables -A FORWARD -p tcp --syn -j DROP
    
    # Block invalid TCP flag combinations
    iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "NULL-PACKET: " --log-level 4
    iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j DROP
    
    iptables -A FORWARD -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "XMAS-PACKET: " --log-level 4
    iptables -A FORWARD -p tcp --tcp-flags ALL ALL -j DROP
    
    # Allow LAN to WAN traffic
    iptables -A FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT
    
    # Block LAN to LAN (client isolation)
    iptables -A FORWARD -i "$LAN_IFACE" -o "$LAN_IFACE" -j LOG --log-prefix "CLIENT-ISOLATION: " --log-level 4
    iptables -A FORWARD -i "$LAN_IFACE" -o "$LAN_IFACE" -j DROP
    
    # Block common P2P and malware ports
    local blocked_ports=(1337 6881 6882 6883 6884 6885 6886 6887 6888 6889 4662)
    for port in "${blocked_ports[@]}"; do
        iptables -A FORWARD -p tcp --dport "$port" -j LOG --log-prefix "BLOCKED-PORT-$port: " --log-level 4
        iptables -A FORWARD -p tcp --dport "$port" -j DROP
        iptables -A FORWARD -p udp --dport "$port" -j LOG --log-prefix "BLOCKED-PORT-$port: " --log-level 4
        iptables -A FORWARD -p udp --dport "$port" -j DROP
    done
    
    # Log and drop everything else
    iptables -A FORWARD -j LOG_DROP
}

setup_output_rules() {
    log "Setting up OUTPUT chain rules..."
    
    # Allow all outbound traffic by default (already set in policy)
    # Could add restrictions here for additional security
    
    # Optional: Restrict outbound connections
    # iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    # iptables -A OUTPUT -o lo -j ACCEPT
    # iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT   # HTTP
    # iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
    # iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT   # DNS TCP
    # iptables -A OUTPUT -p udp --dport 53 -j ACCEPT   # DNS UDP
    # iptables -A OUTPUT -p udp --dport 67 -j ACCEPT   # DHCP
    # iptables -A OUTPUT -p udp --dport 123 -j ACCEPT  # NTP
    # iptables -A OUTPUT -j LOG_DROP
}

setup_nat_rules() {
    log "Setting up NAT rules..."
    
    # Masquerade outgoing traffic
    iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE
    
    # Optional: Port forwarding examples (commented out)
    # iptables -t nat -A PREROUTING -i "$WAN_IFACE" -p tcp --dport 8080 -j DNAT --to-destination 192.168.8.100:80
    # iptables -A FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" -p tcp --dport 80 -d 192.168.8.100 -j ACCEPT
}

setup_mangle_rules() {
    log "Setting up MANGLE rules for QoS..."
    
    # Mark packets for QoS
    # High priority: VoIP, gaming
    iptables -t mangle -A FORWARD -p udp --dport 5060 -j MARK --set-mark 1  # SIP
    iptables -t mangle -A FORWARD -p udp --dport 5004 -j MARK --set-mark 1  # RTP
    iptables -t mangle -A FORWARD -p tcp --dport 22 -j MARK --set-mark 1     # SSH
    
    # Medium priority: Web browsing
    iptables -t mangle -A FORWARD -p tcp --dport 80 -j MARK --set-mark 2     # HTTP
    iptables -t mangle -A FORWARD -p tcp --dport 443 -j MARK --set-mark 2    # HTTPS
    iptables -t mangle -A FORWARD -p tcp --dport 53 -j MARK --set-mark 2     # DNS TCP
    iptables -t mangle -A FORWARD -p udp --dport 53 -j MARK --set-mark 2     # DNS UDP
    
    # Low priority: File transfers, P2P
    iptables -t mangle -A FORWARD -p tcp --dport 21 -j MARK --set-mark 3     # FTP
    iptables -t mangle -A FORWARD -p tcp --dport 20 -j MARK --set-mark 3     # FTP-DATA
}

save_rules() {
    log "Saving iptables rules..."
    
    # Save rules (method depends on distribution)
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.rules 2>/dev/null || \
        log "Warning: Could not save iptables rules automatically"
    fi
    
    # For systemd systems
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    fi
}

show_status() {
    log "Firewall status:"
    echo
    echo "=== FILTER TABLE ==="
    iptables -L -n -v --line-numbers
    echo
    echo "=== NAT TABLE ==="
    iptables -t nat -L -n -v --line-numbers
    echo
    echo "=== MANGLE TABLE ==="
    iptables -t mangle -L -n -v --line-numbers
}

main() {
    log "Configuring advanced firewall rules..."
    log "WAN Interface: $WAN_IFACE"
    log "LAN Interface: $LAN_IFACE"
    log "AP Subnet: $AP_SUBNET"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root"
        exit 1
    fi
    
    # Setup firewall
    flush_rules
    set_default_policies
    create_custom_chains
    setup_anti_ddos
    setup_port_scan_detection
    setup_invalid_packet_protection
    setup_ssh_protection
    setup_logging_chains
    setup_input_rules
    setup_forward_rules
    setup_output_rules
    setup_nat_rules
    setup_mangle_rules
    
    # Save rules
    save_rules
    
    log "✅ Advanced firewall configuration completed"
    
    # Show status if requested
    if [[ "${1:-}" == "status" ]]; then
        show_status
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

