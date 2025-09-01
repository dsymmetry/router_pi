# Troubleshooting Guide

## MT7612U Not Detected
```bash
lsusb | grep 0e8d:7612
sudo ./router_pi_secure.sh reset
```

## No WiFi Network
```bash
sudo systemctl status hostapd
sudo journalctl -u hostapd -n 50
```

## No Internet
```bash
ping 1.1.1.1
sudo iptables -t nat -L POSTROUTING -v
```
