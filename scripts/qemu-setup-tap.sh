#!/bin/bash
# =============================================================================
# QEMU network setup for HTTPS-Guard eBPF/XDP testing
#
# Bridge mode works on all platforms including AST2600 (johnblue):
# - AST2600: Uses built-in ftgmac100 with `-net nic,netdev=net2`
# - x86_64/aarch64: Uses virtio-net-device with `-device virtio-net-device,netdev=net2`
#
# Usage:
#   sudo ./scripts/qemu-setup-tap.sh [create|destroy]
# =============================================================================
set -euo pipefail

BRIDGE="br-httpsguard"
TAP="tap-httpsguard"
TAP_USER="${SUDO_USER:-${USER:-$(id -un)}}"

# Bridge IP (host side). Guest should use 192.168.100.2/24
BRIDGE_IP="192.168.100.1/24"

action="${1:-create}"

case "$action" in
    create)
        echo "[+] Creating bridge $BRIDGE ..."
        sudo ip link add name "$BRIDGE" type bridge 2>/dev/null || echo "    (bridge $BRIDGE already exists)"

        echo "[+] Creating TAP device $TAP for user $TAP_USER ..."
        sudo ip tuntap add dev "$TAP" mode tap user "$TAP_USER" 2>/dev/null || echo "    (tap $TAP already exists)"

        echo "[+] Attaching $TAP to $BRIDGE ..."
        sudo ip link set "$TAP" master "$BRIDGE"

        echo "[+] Assigning IP $BRIDGE_IP to $BRIDGE ..."
        sudo ip addr add "$BRIDGE_IP" dev "$BRIDGE" 2>/dev/null || echo "    (IP already assigned)"

        echo "[+] Bringing links up ..."
        sudo ip link set "$TAP" up
        sudo ip link set "$BRIDGE" up

        echo "[+] Done. Bridge $BRIDGE ready with TAP $TAP."
        echo ""
        echo "    Bridge IP: $BRIDGE_IP (host side)"
        echo ""
        echo "    For AST2600 (johnblue):"
        echo "      QB_NET=none runqemu johnblue nographic \\"
        echo "        qemuparams='-netdev tap,id=net2,ifname=$TAP,script=no,downscript=no -net nic,netdev=net2'"
        echo ""
        echo "    For virtio-capable platforms (x86_64, aarch64-virt):"
        echo "      QB_NET=none runqemu <machine> nographic \\"
        echo "        qemuparams='-netdev tap,id=net2,ifname=$TAP,script=no,downscript=no -device virtio-net-device,netdev=net2'"
        echo ""
        echo "    Inside the guest:"
        echo "      ip addr add 192.168.100.2/24 dev eth0"
        echo "      ip link set eth0 up"
        echo "      ip route add default via 192.168.100.1"
        echo "      echo 'nameserver 8.8.8.8' > /etc/resolv.conf"
        echo ""
        echo "    Test connectivity from host:"
        echo "      ping -c 3 192.168.100.2"
        echo "      curl -k https://192.168.100.2/redfish/v1"
        ;;
    destroy)
        echo "[-] Removing IP $BRIDGE_IP from $BRIDGE ..."
        sudo ip addr del "$BRIDGE_IP" dev "$BRIDGE" 2>/dev/null || true

        echo "[-] Destroying TAP $TAP ..."
        sudo ip link set "$TAP" down 2>/dev/null || true
        sudo ip tuntap del dev "$TAP" mode tap 2>/dev/null || true

        echo "[-] Destroying bridge $BRIDGE ..."
        sudo ip link set "$BRIDGE" down 2>/dev/null || true
        sudo ip link delete "$BRIDGE" type bridge 2>/dev/null || true

        echo "[-] Done."
        ;;
    *)
        echo "Usage: $0 [create|destroy]"
        exit 1
        ;;
esac
