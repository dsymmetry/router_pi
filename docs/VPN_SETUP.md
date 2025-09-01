# VPN Configuration

## WireGuard Setup
```bash
sudo apt-get install wireguard
wg genkey | tee privatekey | wg pubkey > publickey
```

## OpenVPN Setup
```bash
sudo apt-get install openvpn
sudo openvpn --config /etc/openvpn/client/config.ovpn
```
