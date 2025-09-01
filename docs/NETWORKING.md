# Network Configuration

## Default Settings
- Router IP: 192.168.8.1
- DHCP Range: 192.168.8.10-50
- DNS: 1.1.1.1, 9.9.9.9

## MT7612U Configuration
- 5GHz: Channel 36 (default)
- 2.4GHz: Channel 6
- Mode: Access Point

## Custom Configuration

```bash
# Use 2.4GHz
USE_5GHZ=false sudo ./router_pi_secure.sh start

# Custom IP range
AP_ADDR="10.0.0.1/24" sudo ./router_pi_secure.sh start
```
