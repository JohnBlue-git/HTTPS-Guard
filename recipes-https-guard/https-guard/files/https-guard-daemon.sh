#!/bin/sh
# HTTPS-Guard daemon wrapper
# Reads /etc/default/https-guard and launches https-guardd (the real eBPF daemon)
# using the paths installed on the target image.
#
# This service is auto-enabled at build-time via PACKAGECONFIG=daemon/both
# in the bitbake recipe. If it's running, the daemon should be active.
set -eu

CONF_FILE="/etc/default/https-guard"
[ -f "$CONF_FILE" ] && . "$CONF_FILE"

DAEMON="/usr/sbin/https-guardd"
BPF_OBJ="${HTTPS_GUARD_BPF_OBJ:-/usr/share/https-guard/https_guard.bpf.o}"
IFACE="${HTTPS_GUARD_IFACE:-eth0}"
SSL_LIB="${HTTPS_GUARD_SSL_LIB:-/usr/lib/x86_64-linux-gnu/libssl.so.3}"
OUTPUT="${HTTPS_GUARD_EVENT_FILE:-/var/log/https_guard_events.log}"

# Verify the daemon binary exists
if [ ! -x "$DAEMON" ]; then
    echo "https-guard-daemon: ERROR: $DAEMON not found or not executable" >&2
    exit 1
fi

# Verify the BPF object exists
if [ ! -f "$BPF_OBJ" ]; then
    echo "https-guard-daemon: ERROR: BPF object not found at $BPF_OBJ" >&2
    echo "https-guard-daemon: Did you forget to build the eBPF program?" >&2
    echo "https-guard-daemon: Check that clang-native is available in DEPENDS and the" >&2
    echo "    do_compile:append step ran successfully." >&2
    exit 1
fi

# Ensure the output directory exists
mkdir -p "$(dirname "$OUTPUT")"

ACTION_RUNNER="/usr/sbin/action_runner"

if [ ! -x "$ACTION_RUNNER" ]; then
    echo "https-guard-daemon: ERROR: $ACTION_RUNNER not found or not executable" >&2
    exit 1
fi

echo "https-guard-daemon: starting action runner..."
"$ACTION_RUNNER" &

echo "https-guard-daemon: starting daemon..."
echo "    binary:    $DAEMON"
echo "    bpf_obj:   $BPF_OBJ"
echo "    iface:     $IFACE"
echo "    ssl_lib:   $SSL_LIB"
echo "    output:    $OUTPUT"

# Launch the real daemon with all 4 positional arguments
exec "$DAEMON" "$IFACE" "$SSL_LIB" "$OUTPUT" "$BPF_OBJ"