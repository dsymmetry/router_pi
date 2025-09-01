#!/bin/bash
# Quick connectivity test script

echo "=== Connectivity Test ==="
echo

echo "[1] Interface Status:"
ip link show | grep -E "^[0-9]:" | cut -d: -f2

echo
echo "[2] IP Addresses:"
ip -4 addr show | grep inet | grep -v 127.0.0.1

echo
echo "[3] Routing Table:"
ip route

echo
echo "[4] DNS Test:"
dig +short google.com @1.1.1.1 || echo "DNS failed"

echo
echo "[5] Internet Connectivity:"
ping -c 2 1.1.1.1 || echo "No internet connection"

echo
echo "[6] NAT Status:"
sudo iptables -t nat -L POSTROUTING -n | grep MASQUERADE || echo "NAT not configured"
