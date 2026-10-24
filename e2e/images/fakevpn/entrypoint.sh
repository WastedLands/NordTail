#!/bin/bash
# Env: FAKEVPN_PRIVATE_KEY, FAKEVPN_PEER_PUBLIC_KEY, FAKEVPN_PEER_ADDRESS (e.g. 10.99.0.2/32)
set -euo pipefail
: "${FAKEVPN_PRIVATE_KEY:?}" "${FAKEVPN_PEER_PUBLIC_KEY:?}" "${FAKEVPN_PEER_ADDRESS:?}"

# Hosts with Ubuntu's AppArmor profile for /usr/bin/wg only let it read /etc/wireguard/**.
mkdir -p /etc/wireguard && (umask 077; printf '%s\n' "$FAKEVPN_PRIVATE_KEY" > /etc/wireguard/wg0.key)
sysctl -qw net.ipv4.ip_forward=1
ip link del wg0 2>/dev/null || true
ip link add wg0 type wireguard
wg set wg0 listen-port 51820 private-key /etc/wireguard/wg0.key \
  peer "$FAKEVPN_PEER_PUBLIC_KEY" allowed-ips "$FAKEVPN_PEER_ADDRESS"
ip addr add 10.99.0.1/24 dev wg0
ip link set wg0 up

nft -f - <<'NFT'
table ip fakevpn {
  chain postrouting {
    type nat hook postrouting priority srcnat;
    ip saddr 10.99.0.0/24 oifname "eth0" masquerade
  }
}
NFT
echo "[fakevpn] ready"
exec sleep infinity
