#!/bin/sh
# HTTPS-Guard simulated event generator.
# Writes synthetic security events to the event log at a regular interval.
#
# This service is auto-enabled at build-time via PACKAGECONFIG=simulation/both
# in the bitbake recipe. If it's running, the generator should be active.
set -eu

CONF_FILE="/etc/default/https-guard"
[ -f "$CONF_FILE" ] && . "$CONF_FILE"

INTERVAL="${HTTPS_GUARD_SIMULATE_INTERVAL:-15}"
EVENT_FILE="${HTTPS_GUARD_EVENT_FILE:-/var/log/https_guard_events.log}"

mkdir -p "$(dirname "$EVENT_FILE")"
[ -f "$EVENT_FILE" ] || touch "$EVENT_FILE"

echo "simulated-event-generator started, writing to $EVENT_FILE"

while true; do
    TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cat >> "$EVENT_FILE" <<EOF
{"@odata.type":"#Event.v1_7_0.Event","Name":"Platform Security Anomaly Event","Id":"$TS","Events":[{"EventId":"sim-$TS","Severity":"Critical","MessageId":"OemSecurityEvent.1.0.0.HttpsTlsVersionViolation","Message":"Security violation: Process 'curl' (PID 12043) attempted insecure TLS version (TLS 1.0). Packet was blocked.","MessageArgs":["curl","12043","TLS 1.0"],"EventTimestamp":"$TS","OriginOfCondition":{"@odata.id":"/redfish/v1/Managers/bmc"}}]}
EOF
    sleep "$INTERVAL"
done
