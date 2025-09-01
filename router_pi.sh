#!/bin/bash
# Pi-safe AP router toggle: manages only WLAN AP, keeps WAN DHCP running.
# Works with dhcpcd / NetworkManager / systemd-networkd still handling WAN.

set -euo pipefail

# === CONFIG ===
LAN_IFACE="${LAN_IFACE:-wlan0}"              # AP interface (USB/Wi-Fi)
AP_ADDR="${AP_ADDR:-192.168.8.1/24}"         # AP subnet
DHCP_RANGE="${DHCP_RANGE:-192.168.8.10,192.168.8.50,12h}"
HOSTAPD_CONF="${HOSTAPD_CONF:-/etc/hostapd/hostapd.conf}"
DNSMASQ_DROPIN="/etc/dnsmasq.d/router.conf"
STATE_DIR="/run/routerpi"
mkdir -p "$STATE_DIR"

# Auto-detect WAN by default route if not provided
WAN_IFACE="${WAN_IFACE:-$(ip route | awk '/default/ {print $5; exit}')}"

require() { command -v "$1" >/dev/null 2>&1 || { echo "Missing $1"; exit 1; }; }

start_router() {
  echo "[+] WAN: $WAN_IFACE, LAN/AP: $LAN_IFACE"

  # 0) Ensure needed tools
  require iptables; require ip; require hostapd; require dnsmasq

  # 1) Make sure WAN has an IP (renew but don’t kill the daemon)
  if command -v dhclient >/dev/null 2>&1; then
    sudo dhclient -v "$WAN_IFACE" || true
  elif command -v networkctl >/dev/null 2>&1; then
    sudo networkctl renew "$WAN_IFACE" || true
  elif command -v dhcpcd >/dev/null 2>&1; then
    sudo dhcpcd -n "$WAN_IFACE" || true
  fi

  # 2) Bring AP iface up with static
  sudo ip link set "$LAN_IFACE" down || true
  sudo iw dev "$LAN_IFACE" set type __ap || true
  sudo ip addr flush dev "$LAN_IFACE" || true
  sudo ip addr add "$AP_ADDR" dev "$LAN_IFACE"
  sudo ip link set "$LAN_IFACE" up

  # 3) Enable forwarding (persist in sysctl and runtime)
  sudo sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
  echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf >/dev/null
  sudo sysctl -w net.ipv4.ip_forward=1

  # 4) NAT + FORWARD (idempotent)
  sudo iptables -C FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || \
    sudo iptables -A FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT
  sudo iptables -C FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    sudo iptables -A FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
  sudo iptables -t nat -C POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || \
    sudo iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE

  # Save current FORWARD policy to restore on stop
  sudo iptables -S FORWARD | head -n1 > "$STATE_DIR/forward_policy" 2>/dev/null || true
  # Ensure policy isn’t blocking
  sudo iptables -P FORWARD ACCEPT

  # 5) dnsmasq drop-in (gateway + DNS for clients)
  echo -e "interface=$LAN_IFACE\ndhcp-range=$DHCP_RANGE\ndhcp-option=3,${AP_ADDR%/*}\ndhcp-option=6,1.1.1.1,8.8.8.8\nbind-interfaces" \
    | sudo tee "$DNSMASQ_DROPIN" >/dev/null
  sudo systemctl restart dnsmasq

  # 6) hostapd via systemd if configured, else run direct
  if grep -q '^DAEMON_CONF=' /etc/default/hostapd 2>/dev/null; then
    sudo systemctl unmask hostapd 2>/dev/null || true
    sudo systemctl restart hostapd
  else
    sudo pkill hostapd 2>/dev/null || true
    sudo hostapd "$HOSTAPD_CONF" -B
  fi

  # 7) Final checks
  echo "[i] Default route: $(ip route | awk '/default/ {print $0}')"
  echo "[i] NAT table:"
  sudo iptables -t nat -L POSTROUTING -n -v | sed -n '1,5p'
  echo "[✓] Router started: SSID should be visible; clients should get IP + internet."
}

stop_router() {
  echo "[+] Stopping AP + DHCP"
  # Stop hostapd
  if systemctl is-enabled hostapd >/dev/null 2>&1 || systemctl is-active hostapd >/dev/null 2>&1; then
    sudo systemctl stop hostapd || true
  else
    sudo pkill hostapd 2>/dev/null || true
  fi
  sudo systemctl stop dnsmasq || true

  # Remove dnsmasq drop-in
  if [ -f "$DNSMASQ_DROPIN" ]; then
    sudo rm -f "$DNSMASQ_DROPIN"
    sudo systemctl restart dnsmasq || true
  fi

  # Remove iptables rules if present
  sudo iptables -D FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || true
  sudo iptables -D FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  sudo iptables -t nat -D POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || true

  # Restore FORWARD policy if we saved it
  if [ -f "$STATE_DIR/forward_policy" ]; then
    POLICY_LINE=$(cat "$STATE_DIR/forward_policy")
    case "$POLICY_LINE" in
      *" -P FORWARD ACCEPT"*) sudo iptables -P FORWARD ACCEPT ;;
      *" -P FORWARD DROP"*)   sudo iptables -P FORWARD DROP ;;
      *" -P FORWARD REJECT"*) sudo iptables -P FORWARD REJECT ;;
      *) true ;;
    esac
    rm -f "$STATE_DIR/forward_policy" || true
  fi

  # Return LAN iface to managed + down (optional)
  sudo ip link set "$LAN_IFACE" down || true
  sudo iw dev "$LAN_IFACE" set type managed || true

  # Renew WAN so the Pi regains internet immediately
  if command -v dhclient >/dev/null 2>&1; then
    sudo dhclient -v -r "$WAN_IFACE" || true
    sudo dhclient -v "$WAN_IFACE" || true
  elif command -v networkctl >/dev/null 2>&1; then
    sudo networkctl renew "$WAN_IFACE" || true
  elif command -v dhcpcd >/dev/null 2>&1; then
    sudo dhcpcd -n "$WAN_IFACE" || true
  fi

  echo "[✓] Router stopped and WAN renewed; your Pi should have internet now."
}

status_router() {
  echo "=== Status ==="
  ip -4 a show "$WAN_IFACE" | sed 's/^/WAN: /'
  ip -4 a show "$LAN_IFACE" | sed 's/^/LAN: /'
  echo
  echo "Default route:"
  ip route | awk '/default/ {print}'
  echo
  echo "NAT POSTROUTING:"
  sudo iptables -t nat -L POSTROUTING -n -v | sed -n '1,10p'
  echo
  systemctl is-active hostapd >/dev/null 2>&1 && echo "hostapd: active" || echo "hostapd: inactive"
  systemctl is-active dnsmasq >/dev/null 2>&1 && echo "dnsmasq: active" || echo "dnsmasq: inactive"
}

case "${1:-}" in
  start)  start_router ;;
  stop)   stop_router ;;
  status) status_router ;;
  *)      echo "Usage: $0 {start|stop|status}"; exit 1 ;;
esac
