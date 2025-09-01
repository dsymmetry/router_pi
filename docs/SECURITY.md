# Security Documentation

## Security Features

1. **Firewall**: Stateful iptables with rate limiting
2. **IDS/IPS**: Real-time monitoring with auto-blocking
3. **WiFi Security**: WPA2/WPA3 with strong passwords
4. **DNS Security**: DNSSEC and rebinding protection
5. **System Hardening**: IPv6 disabled, minimal services

## Running Security Audit

```bash
sudo ./router_pi_secure.sh audit
```
