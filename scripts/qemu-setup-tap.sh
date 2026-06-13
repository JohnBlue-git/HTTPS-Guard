#!/bin/bash
# =============================================================================
# QEMU TAP/bridge network setup for HTTPS-Guard eBPF/XDP testing
#
# This script creates a TAP device and bridge on the host, allowing the
# QEMU guest to have a real virtio-net device that supports XDP generic
# mode. Run this before launching QEMU with TAP networking.
#
# Usage:
#   sudo ./scripts/qemu-setup-tap.sh [create|destroy]
#
# After creating the bridge, build and run the QEMU image with:
#   bitbake obmc-phosphor-image -R <(echo 'QB_NETWORK_OPTION = "-netdev tap,id=net0,ifname=tap0,script=no,downscript=no -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56"')
#   runqemu johnblue nographic
#
# Inside the guest, verify XDP works:
#   ip link set eth0 xdp obj /usr/share/https-guard/https_guard.bpf.o sec xdp
#   ip link show eth0
# =============================================================================
set -euo pipefail

BRIDGE="br-httpsguard"
TAP="tap-httpsguard"
MAC="52:54:00:12:34:56"

action="${1:-create}"

case "$action" in
    create)
        echo "[+] Creating bridge $BRIDGE ..."
        sudo ip link add name "$BRIDGE" type bridge 2>/dev/null || echo "    (bridge $BRIDGE already exists)"

        echo "[+] Creating TAP device $TAP ..."
        sudo ip tuntap add dev "$TAP" mode tap user "$(whoami)" 2>/dev/null || echo "    (tap $TAP already exists)"

        echo "[+] Attaching $TAP to $BRIDGE ..."
        sudo ip link set "$TAP" master "$BRIDGE"

        echo "[+] Bringing links up ..."
        sudo ip link set "$TAP" up
        sudo ip link set "$BRIDGE" up

        echo "[+] Done. Bridge $BRIDGE ready with TAP $TAP."
        echo ""
        echo "    Build and run QEMU with:"
        echo "      QB_NETWORK_OPTION='-netdev tap,id=net0,ifname=$TAP,script=no,downscript=no -device virtio-net-pci,netdev=net0,mac=$MAC'"
        echo "      runqemu johnblue nographic"
        echo ""
        echo "    Inside the guest (after login):"
        echo "      # Set HTTPS_GUARD_DAEMON_ENABLE=1 in /etc/default/https-guard"
        echo "      # systemctl start https-guard-daemon.service"
        echo "      # journalctl -u https-guard-daemon -f"
        echo ""
        echo "    Guest network interface will be available at e.g. 192.168.42.15"
        echo "    (assign via DHCP or static config inside the BMC)."
        ;;
    destroy)
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