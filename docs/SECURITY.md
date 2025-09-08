# 🔐 Security Documentation

## Overview

The RPi5 Secure Router implements multiple layers of security to create a hardened travel router suitable for hostile network environments. This document details all security features and their configuration.

## 🛡️ Security Architecture

### Multi-Layer Defense Strategy

1. **Network Layer**: Advanced firewall with DDoS protection
2. **Application Layer**: Secure DNS with malware blocking
3. **Wireless Layer**: WPA2/WPA3 with client isolation
4. **System Layer**: Kernel hardening and service minimization
5. **Monitoring Layer**: Real-time threat detection and logging

## 🔥 Firewall Security

### Advanced iptables Configuration

The firewall implements a comprehensive security model:

- **Default DROP Policy**: All traffic denied by default
- **Stateful Connection Tracking**: Only established connections allowed
- **Rate Limiting**: Per-IP connection and packet rate limits
- **DDoS Protection**: SYN flood and connection flood protection
- **Port Scan Detection**: Automatic detection and blocking
- **Invalid Packet Filtering**: Malformed packet protection

### Key Security Rules

```bash
# Connection limits per IP
MAX_CONN_PER_IP=20

# Rate limiting
RATE_LIMIT=50/sec
BURST_LIMIT=20

# SSH protection
SSH_RATE_LIMIT=4 attempts per minute
```

### Custom Security Chains

- `DDOS_PROTECTION`: Anti-DDoS measures
- `RATE_LIMIT`: Per-IP rate limiting
- `PORT_SCAN`: Port scan detection
- `SSH_PROTECTION`: SSH brute-force protection
- `INVALID_PACKETS`: Malformed packet filtering

## 📶 WiFi Security

### WPA2/WPA3 Configuration

- **Encryption**: AES-256-CCMP (WPA2) with SAE (WPA3) support
- **Key Management**: WPA-PSK with optional SAE
- **Password Generation**: 25-character cryptographically secure passwords
- **Client Isolation**: AP isolation prevents client-to-client communication
- **Hidden SSID**: Optional SSID hiding capability

### MT7612U Optimizations

- **802.11ac Support**: Full 5GHz 802.11ac with VHT capabilities
- **Dual Band**: 2.4GHz (802.11n) and 5GHz (802.11ac) support
- **Security Features**: Management frame protection, disassociation protection
- **Performance**: Optimized HT/VHT capabilities for maximum throughput

## 🔍 DNS Security

### Secure DNS Configuration

- **Upstream Servers**: Cloudflare (1.1.1.1), Quad9 (9.9.9.9), Google (8.8.8.8)
- **DNS Rebinding Protection**: Prevents DNS rebinding attacks
- **Malware Blocking**: Built-in blocklist for known malicious domains
- **Privacy Protection**: No query forwarding without domain part
- **Cache Security**: Optimized cache with negative TTL

### Ad and Malware Blocking

Built-in blocking for:
- Advertising networks (Google Ads, Facebook, etc.)
- Analytics and tracking
- Cryptocurrency mining scripts
- Known malware domains
- Phishing sites

## 🔒 System Hardening

### Kernel Security

```bash
# IPv6 disabled (reduced attack surface)
net.ipv6.conf.all.disable_ipv6 = 1

# Network security
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
```

### Service Security

- **Minimal Services**: Only essential services enabled
- **SSH Hardening**: LAN-only access with rate limiting
- **File Permissions**: Sensitive files protected (600 permissions)
- **Process Isolation**: Services run with minimal privileges

## 🚨 Intrusion Detection System (IDS)

### Suricata Integration

- **Real-time Monitoring**: Network traffic analysis
- **Signature-based Detection**: Known attack pattern detection
- **Anomaly Detection**: Behavioral analysis for unknown threats
- **Auto-blocking**: Automatic IP blocking for detected threats

### Threat Response

- **Automatic Blocking**: Malicious IPs blocked for 1 hour (configurable)
- **Logging**: All security events logged with timestamps
- **Alert Escalation**: Critical threats logged to security log
- **Recovery**: Automatic unblocking after timeout

## 📊 Security Monitoring

### Real-time Monitoring

- **Traffic Analysis**: Continuous network traffic monitoring
- **Connection Tracking**: Active connection monitoring
- **Resource Monitoring**: CPU, memory, and temperature tracking
- **Adapter Health**: MT7612U adapter health monitoring

### Security Logging

Log files located in `/var/log/routerpi/`:
- `security.log`: Security events and threats
- `traffic.log`: Network traffic statistics
- `router.log`: General router operations
- `mt7612u_monitor.log`: Adapter health monitoring

## 🔧 Security Audit

### Automated Security Assessment

Run comprehensive security audit:

```bash
sudo ./router_pi_secure.sh audit
```

### Audit Categories

1. **Firewall Analysis**: Rule verification and policy check
2. **Service Security**: Service configuration and status
3. **System Hardening**: Kernel and system security settings
4. **Network Security**: Interface and routing security
5. **Password Security**: WiFi password strength analysis
6. **Logging Monitoring**: Log configuration and monitoring status

### Quick Security Check

```bash
sudo ./scripts/security_audit.sh quick
```

## 🛠️ Security Tools

### Network Diagnostics

```bash
# Full network diagnostic
sudo ./scripts/network_diag.sh full

# Connectivity test
sudo ./scripts/network_diag.sh connectivity

# Real-time monitoring
sudo ./scripts/network_diag.sh monitor
```

### MT7612U Monitoring

```bash
# Adapter health check
sudo ./scripts/mt7612u_monitor.sh check

# Adapter statistics
sudo ./scripts/mt7612u_monitor.sh stats

# Reset adapter
sudo ./scripts/mt7612u_monitor.sh reset
```

### VPN Security

```bash
# Check VPN support
sudo ./scripts/vpn_setup.sh check

# Setup WireGuard VPN with integrated kill switch
ENABLE_VPN=true sudo ./router_pi_secure.sh start

# VPN status
sudo ./scripts/vpn_setup.sh status
```

## 🚨 Incident Response

### Threat Detection Response

1. **Automatic Actions**: Immediate IP blocking for detected threats
2. **Logging**: All incidents logged with full details
3. **Alert Generation**: Security events written to security log
4. **Recovery**: Automatic unblocking after configured timeout

### Manual Response

```bash
# View recent security events
tail -f /var/log/routerpi/security.log

# Check blocked IPs
cat /run/routerpi/blocked_ips

# Manual IP blocking
iptables -I INPUT -s MALICIOUS_IP -j DROP

# View firewall logs
journalctl -f | grep "ROUTER-DROP"
```

## 🔐 Security Best Practices

### Operational Security

1. **Regular Updates**: Keep system packages updated
2. **Password Rotation**: Change WiFi password periodically
3. **Log Monitoring**: Regularly review security logs
4. **Firmware Updates**: Keep router firmware updated
5. **Configuration Backup**: Backup security configurations

### Travel Security

1. **VPN Usage**: Always use VPN in untrusted networks
2. **Client Isolation**: Keep AP isolation enabled
3. **Hidden SSID**: Consider hiding SSID in hostile environments
4. **WireGuard VPN**: Use integrated WireGuard VPN with kill switch
5. **Regular Audits**: Run security audits before deployment

### Emergency Procedures

1. **Adapter Reset**: Use MT7612U reset if connectivity issues
2. **Firewall Reset**: Emergency firewall flush if locked out
3. **Factory Reset**: Complete router reset if compromised
4. **Incident Logging**: Document all security incidents

## 📋 Security Checklist

### Pre-deployment

- [ ] Run security audit
- [ ] Verify firewall rules
- [ ] Check WiFi password strength
- [ ] Confirm service hardening
- [ ] Test VPN connectivity
- [ ] Verify logging configuration

### Post-deployment

- [ ] Monitor security logs
- [ ] Check for blocked IPs
- [ ] Verify adapter health
- [ ] Monitor resource usage
- [ ] Test connectivity
- [ ] Review threat detection

### Maintenance

- [ ] Update system packages
- [ ] Rotate WiFi password
- [ ] Review security logs
- [ ] Update threat signatures
- [ ] Backup configurations
- [ ] Test emergency procedures

## 🚨 Security Alerts

### Critical Alerts

- Multiple failed SSH attempts
- Port scan detection
- DDoS attack detection
- VPN connection failures
- Adapter hardware failures

### Warning Alerts

- High connection rates
- Unusual traffic patterns
- DNS resolution failures
- High system resource usage
- Configuration changes

## 📞 Support and Resources

### Log Analysis

```bash
# Security events
grep "SECURITY:" /var/log/routerpi/*.log

# Firewall drops
grep "ROUTER-DROP" /var/log/syslog

# SSH attempts
grep "SSH-BRUTE-FORCE" /var/log/syslog

# Port scans
grep "PORTSCAN-DETECTED" /var/log/syslog
```

### Performance Monitoring

```bash
# System resources
sudo ./router_pi_secure.sh status

# Network performance
sudo ./scripts/network_diag.sh performance

# Traffic monitoring
sudo ./scripts/network_diag.sh monitor
```

This comprehensive security implementation provides enterprise-grade protection suitable for use in hostile network environments while maintaining usability and performance.
