# OpenBMC + QEMU integration guide

This guide provides a simple integration path for HTTPS-Guard into OpenBMC QEMU images.

## What this integration does

- Adds a custom Yocto layer: openbmc/meta-https-guard.
- Installs two services:
  - https-guard-event-generator.service: simulates eBPF anomaly signals in QEMU.
  - https-guard-event-bridge.service: bridges events to DBus Logging and/or Journal.
- Keeps bmcweb EventService flow unchanged:
  - DBus signal path: phosphor-logging Create API (mainstream path).
  - Journal path: systemd journal entries for log-based monitoring path.

## Quick start

1. Run the setup script:

```bash
chmod +x scripts/openbmc_qemu_setup.sh
scripts/openbmc_qemu_setup.sh ~/openbmc
```

2. Boot image:

```bash
cd ~/openbmc/build/qemuarm
runqemu nographic slirp
```

3. Validate services in QEMU:

```bash
systemctl status https-guard-event-generator.service
systemctl status https-guard-event-bridge.service
```

4. Validate DBus logging path:

```bash
journalctl -u xyz.openbmc_project.Logging.service -f
busctl tree xyz.openbmc_project.Logging
```

5. Validate Redfish EventService is available on bmcweb:

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
