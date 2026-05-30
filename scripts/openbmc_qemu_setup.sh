#!/usr/bin/env bash
set -euo pipefail

# Simple bootstrap for stable OpenBMC + HTTPS-Guard layer in QEMU.
OPENBMC_DIR="${1:-$HOME/openbmc}" 
OPENBMC_BRANCH="${OPENBMC_BRANCH:-scarthgap}"
THIS_REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v repo >/dev/null 2>&1; then
  echo "repo command not found. Install repo first."
  exit 1
fi

mkdir -p "$OPENBMC_DIR"
cd "$OPENBMC_DIR"

if [ ! -d .repo ]; then
  repo init -u https://github.com/openbmc/openbmc.git -b "$OPENBMC_BRANCH"
fi

repo sync -j"$(nproc)"

if [ -d meta-https-guard ]; then
  rm -rf meta-https-guard
fi
cp -a "$THIS_REPO_DIR/openbmc/meta-https-guard" ./meta-https-guard

if [ ! -f setup ]; then
  echo "OpenBMC setup script not found under $OPENBMC_DIR"
  exit 1
fi

TEMPLATE="qemuarm"
source ./setup "$TEMPLATE"

AUTO_CONF="build/$TEMPLATE/conf/auto.conf"
mkdir -p "$(dirname "$AUTO_CONF")"

append_if_missing() {
  local line="$1"
  if ! grep -Fq "$line" "$AUTO_CONF" 2>/dev/null; then
    echo "$line" >> "$AUTO_CONF"
  fi
}

append_if_missing 'BBLAYERS:append = " ${TOPDIR}/../meta-https-guard"'
append_if_missing 'IMAGE_INSTALL:append = " https-guard-openbmc"'
append_if_missing 'DISTRO_FEATURES:append = " systemd"'

bitbake obmc-phosphor-image

cat <<EOF
Build complete.
Run QEMU with:
  runqemu nographic slirp
In QEMU shell, verify services:
  systemctl status https-guard-event-generator.service
  systemctl status https-guard-event-bridge.service
Check DBus logging output:
  busctl tree xyz.openbmc_project.Logging
  journalctl -u https-guard-event-bridge -f
EOF
