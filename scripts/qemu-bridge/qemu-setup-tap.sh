#!/bin/bash
# =============================================================================
# QEMU network setup for HTTPS-Guard eBPF/XDP testing
#
# Creates: br-httpsguard (192.168.200.1/24) + tap-httpsguard + NAT masquerade
# Guest should use 192.168.200.2/24 with gateway 192.168.200.1
#
# Usage:
#   sudo ./scripts/qemu-bridge/qemu-setup-tap.sh [create|destroy]
# =============================================================================
set -euo pipefail

BRIDGE="br-httpsguard"
TAP="tap-httpsguard"
TAP_USER="${SUDO_USER:-${USER:-$(id -un)}}"

BRIDGE_IP="192.168.200.1/24"
BRIDGE_NET="192.168.200.0/24"

# Auto-detect the host interface used for internet access
HOST_IF=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)

action="${1:-create}"

case "$action" in
    create)
        echo "[+] Creating bridge $BRIDGE ..."
        ip link add name "$BRIDGE" type bridge 2>/dev/null || echo "    (bridge $BRIDGE already exists)"

        echo "[+] Creating TAP device $TAP for user $TAP_USER ..."
        ip tuntap add dev "$TAP" mode tap user "$TAP_USER" 2>/dev/null || echo "    (tap $TAP already exists)"

        echo "[+] Attaching $TAP to $BRIDGE ..."
        ip link set "$TAP" master "$BRIDGE"

        echo "[+] Assigning IP $BRIDGE_IP to $BRIDGE ..."
        ip addr add "$BRIDGE_IP" dev "$BRIDGE" 2>/dev/null || echo "    (IP already assigned)"

        echo "[+] Bringing links up ..."
        ip link set "$TAP" up
        ip link set "$BRIDGE" up

        echo "[+] Enabling IP forwarding and NAT (via $HOST_IF) ..."
        echo 1 > /proc/sys/net/ipv4/ip_forward
        iptables -t nat -C POSTROUTING -s "$BRIDGE_NET" -o "$HOST_IF" -j MASQUERADE 2>/dev/null || \
            iptables -t nat -A POSTROUTING -s "$BRIDGE_NET" -o "$HOST_IF" -j MASQUERADE
        iptables -C FORWARD -i "$BRIDGE" -o "$HOST_IF" -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "$BRIDGE" -o "$HOST_IF" -j ACCEPT
        iptables -C FORWARD -i "$HOST_IF" -o "$BRIDGE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "$HOST_IF" -o "$BRIDGE" -m state --state RELATED,ESTABLISHED -j ACCEPT

        echo ""
        echo "[+] Done. Bridge $BRIDGE ready with TAP $TAP."
        echo "    Bridge IP: $BRIDGE_IP (host side)"
        echo ""
        echo "    Launch QEMU (AST2600 / johnblue):"
        echo "      QB_NET=none runqemu johnblue nographic \\"
        echo "        qemuparams='-netdev tap,id=net0,ifname=$TAP,script=no,downscript=no -net nic,netdev=net0'"
        echo ""
        echo "    Inside the guest (as root):"
        echo "      ip addr add 192.168.200.2/24 dev eth0"
        echo "      ip link set eth0 up"
        echo "      ip route add default via 192.168.200.1"
        echo "      echo 'nameserver 8.8.8.8' > /etc/resolv.conf"
        echo ""
        echo "    Verify from host:"
        echo "      ping -c 3 192.168.200.2"
        echo "      curl -k https://192.168.200.2/redfish/v1"
        ;;
    destroy)
        echo "[-] Removing NAT rules ..."
        iptables -t nat -D POSTROUTING -s "$BRIDGE_NET" -o "$HOST_IF" -j MASQUERADE 2>/dev/null || true
        iptables -D FORWARD -i "$BRIDGE" -o "$HOST_IF" -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -i "$HOST_IF" -o "$BRIDGE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

        echo "[-] Removing IP $BRIDGE_IP from $BRIDGE ..."
        ip addr del "$BRIDGE_IP" dev "$BRIDGE" 2>/dev/null || true

        echo "[-] Destroying TAP $TAP ..."
        ip link set "$TAP" down 2>/dev/null || true
        ip tuntap del dev "$TAP" mode tap 2>/dev/null || true

        echo "[-] Destroying bridge $BRIDGE ..."
        ip link set "$BRIDGE" down 2>/dev/null || true
        ip link delete "$BRIDGE" type bridge 2>/dev/null || true

        echo "[-] Done."
        ;;
    *)
        echo "Usage: $0 [create|destroy]"
        exit 1
        ;;
esac
