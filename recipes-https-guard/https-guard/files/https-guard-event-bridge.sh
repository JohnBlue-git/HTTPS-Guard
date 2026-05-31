#!/bin/sh
set -eu

CONF_FILE="/etc/default/https-guard"
[ -f "$CONF_FILE" ] && . "$CONF_FILE"

EVENT_FILE="${HTTPS_GUARD_EVENT_FILE:-/var/log/redfish/https_guard_events.log}"
MODE="${HTTPS_GUARD_EVENT_MODE:-both}"

mkdir -p "$(dirname "$EVENT_FILE")"
[ -f "$EVENT_FILE" ] || touch "$EVENT_FILE"

emit_dbus_log() {
    msg_id="$1"
    msg="$2"
    sev="$3"

    case "$sev" in
        Critical|critical) level="xyz.openbmc_project.Logging.Entry.Level.Critical" ;;
        Warning|warning) level="xyz.openbmc_project.Logging.Entry.Level.Warning" ;;
        *) level="xyz.openbmc_project.Logging.Entry.Level.Informational" ;;
    esac

    busctl call \
      xyz.openbmc_project.Logging \
      /xyz/openbmc_project/logging \
      xyz.openbmc_project.Logging.Create \
      Create \
      ssa{ss} \
      "$msg" \
      "$level" \
      1 \
      "REDFISH_MESSAGE_ID" "$msg_id" >/dev/null 2>&1 || true
}

extract_field() {
    line="$1"
    key="$2"
    echo "$line" | sed -n "s/.*\"$key\":\"\([^\"]*\)\".*/\1/p"
}

echo "https-guard-event-bridge started, mode=$MODE, source=$EVENT_FILE"

tail -n 0 -F "$EVENT_FILE" | while IFS= read -r line; do
    msg_id="$(extract_field "$line" "MessageId")"
    sev="$(extract_field "$line" "Severity")"
    msg="$(extract_field "$line" "Message")"

    [ -n "$msg_id" ] || msg_id="OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected"
    [ -n "$sev" ] || sev="Warning"
    [ -n "$msg" ] || msg="HTTPS-Guard observed security anomaly"

    case "$MODE" in
        dbus)
            emit_dbus_log "$msg_id" "$msg" "$sev"
            ;;
        journal)
            echo "$line" | systemd-cat -t https-guard-event -p warning
            ;;
        both|*)
            emit_dbus_log "$msg_id" "$msg" "$sev"
            echo "$line" | systemd-cat -t https-guard-event -p warning
            ;;
    esac
done
