# OpenBMC + QEMU integration guide

This guide provides a simple integration path for HTTPS-Guard into OpenBMC QEMU images.

## What this integration does

- Adds a custom Yocto layer: `recipes-https-guard/https-guard` in the HTTPS-Guard project.
- Installs two services:
  - https-guard-event-generator.service: simulates eBPF anomaly signals in QEMU.
  - https-guard-event-bridge.service: bridges events to DBus Logging and/or Journal.
- Keeps bmcweb EventService flow unchanged:
  - DBus signal path: phosphor-logging Create API (mainstream path).
  - Journal path: systemd journal entries for log-based monitoring path.

## Quick start

1. Initialize the OpenBMC repository using the local manifest:

```bash
mkdir -p ~/openbmc
cd ~/openbmc
repo init -u /path/to/HTTPS-Guard/manifest/main.xml
```

2. Sync all repositories:

```bash
repo sync -j$(nproc)
```

3. Set up the OpenBMC build environment:

```bash
source ./setup qemuarm
```

4. Enable the HTTPS-Guard layer and package by appending to `build/qemuarm/conf/auto.conf`:

```bash
cat >> build/qemuarm/conf/auto.conf <<'EOF'
BBLAYERS:append = " ${TOPDIR}/.."
IMAGE_INSTALL:append = " https-guard-openbmc"
DISTRO_FEATURES:append = " systemd"
EOF
```

5. Build the QEMU image:

```bash
bitbake obmc-phosphor-image
```

6. Start QEMU:

```bash
cd ~/openbmc/build/qemuarm
runqemu nographic slirp
```

7. Validate services in QEMU:

```bash
systemctl status https-guard-event-generator.service
systemctl status https-guard-event-bridge.service
```

8. Validate DBus logging path:

```bash
journalctl -u xyz.openbmc_project.Logging.service -f
busctl tree xyz.openbmc_project.Logging
```

9. Validate Redfish EventService:

```bash
curl -k https://<bmc-ip>/redfish/v1/EventService
```

## Event mode switch

Modify /etc/default/https-guard in QEMU guest:

- HTTPS_GUARD_EVENT_MODE=dbus
- HTTPS_GUARD_EVENT_MODE=journal
- HTTPS_GUARD_EVENT_MODE=both

Then restart bridge:

```bash
systemctl restart https-guard-event-bridge.service
```

## Notes for real eBPF runtime

The generator service is for QEMU simulation convenience. In hardware or a kernel-enabled test image, replace generator with the real https_guardd runtime and keep the same event file contract:

- /var/log/redfish/https_guard_events.log

The bridge service can remain unchanged and continue emitting DBus/Journal events to the OpenBMC stack.
