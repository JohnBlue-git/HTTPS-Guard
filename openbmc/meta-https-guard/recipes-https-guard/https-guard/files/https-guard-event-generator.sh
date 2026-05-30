#!/bin/sh
set -eu

CONF_FILE="/etc/default/https-guard"
[ -f "$CONF_FILE" ] && . "$CONF_FILE"

SIMULATE="${HTTPS_GUARD_SIMULATE:-1}"
INTERVAL="${HTTPS_GUARD_SIMULATE_INTERVAL:-15}"
EVENT_FILE="${HTTPS_GUARD_EVENT_FILE:-/var/log/redfish/https_guard_events.log}"

mkdir -p "$(dirname "$EVENT_FILE")"
[ -f "$EVENT_FILE" ] || touch "$EVENT_FILE"

if [ "$SIMULATE" != "1" ]; then
    echo "https-guard-event-generator disabled (HTTPS_GUARD_SIMULATE=$SIMULATE)"
    tail -f /dev/null
fi

echo "https-guard-event-generator started, writing to $EVENT_FILE"

while true; do
    TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cat >> "$EVENT_FILE" <<EOF
{"@odata.type":"#Event.v1_7_0.Event","Name":"Platform Security Anomaly Event","Id":"$TS","Events":[{"EventId":"sim-$TS","Severity":"Critical","MessageId":"OemSecurityEvent.1.0.0.HttpsTlsVersionViolation","Message":"Security violation: Process 'curl' (PID 12043) attempted insecure TLS version (TLS 1.0). Packet was blocked.","MessageArgs":["curl","12043","TLS 1.0"],"EventTimestamp":"$TS","OriginOfCondition":{"@odata.id":"/redfish/v1/Managers/bmc"}}]}
EOF
    sleep "$INTERVAL"
done
