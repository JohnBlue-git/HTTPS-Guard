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
OUTPUT="${HTTPS_GUARD_EVENT_FILE:-/var/log/https_guard_events.log}"
EXPECTED_SNI="${HTTPS_GUARD_EXPECTED_SNI:-}"
# Empty means "no rate detection"; the daemon treats 0 the same way.
RATE_THRESHOLD="${HTTPS_GUARD_RATE_THRESHOLD:-0}"
SLOWLORIS_THRESHOLD="${HTTPS_GUARD_SLOWLORIS_THRESHOLD:-0}"
RENEG_THRESHOLD="${HTTPS_GUARD_RENEG_THRESHOLD:-0}"

# Auto-detect libssl if not explicitly configured
if [ -n "${HTTPS_GUARD_SSL_LIB:-}" ]; then
    SSL_LIB="$HTTPS_GUARD_SSL_LIB"
else
    SSL_LIB=""
    # Try common paths in order of likelihood on OpenBMC targets
    for candidate in \
        /usr/lib/libssl.so.3 \
        /usr/lib64/libssl.so.3 \
        /usr/lib/aarch64-linux-gnu/libssl.so.3 \
        /usr/lib/arm-linux-gnueabihf/libssl.so.3 \
        /usr/lib/arm-linux-gnueabi/libssl.so.3 \
        /lib/libssl.so.3 \
        /lib64/libssl.so.3
    do
        if [ -f "$candidate" ]; then
            SSL_LIB="$candidate"
            break
        fi
    done

    # Fallback: search via /proc for any process that has libssl mapped
    if [ -z "$SSL_LIB" ]; then
        for pid_dir in /proc/[0-9]*; do
            pid="${pid_dir##*/}"
            maps_file="$pid_dir/maps"
            [ -r "$maps_file" ] || continue
            # Look for libssl.so in the process memory maps
            found=$(grep -h 'libssl\.so' "$maps_file" 2>/dev/null | head -1 | awk '{print $NF}')
            if [ -n "$found" ] && [ -f "$found" ]; then
                SSL_LIB="$found"
                break
            fi
        done
    fi

    if [ -z "$SSL_LIB" ]; then
        echo "https-guard-daemon: WARNING: could not auto-detect libssl.so.3, defaulting to /usr/lib/libssl.so.3" >&2
        SSL_LIB="/usr/lib/libssl.so.3"
    else
        echo "https-guard-daemon: auto-detected libssl at $SSL_LIB" >&2
    fi
fi

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
echo "    sni:       ${EXPECTED_SNI:-(unset)}"
echo "    rate:      ${RATE_THRESHOLD} attempts/window (0 = disabled)"
echo "    slowloris: ${SLOWLORIS_THRESHOLD} open conns (0 = disabled)"
echo "    reneg:     ${RENEG_THRESHOLD} handshakes/window (0 = disabled)"

# Launch the real daemon. The 5th argument (expected SNI) is optional and
# may legitimately be empty — see HTTPS_GUARD_EXPECTED_SNI in the config.
exec "$DAEMON" "$IFACE" "$SSL_LIB" "$OUTPUT" "$BPF_OBJ" "$EXPECTED_SNI" \
     "$RATE_THRESHOLD" "$SLOWLORIS_THRESHOLD" "$RENEG_THRESHOLD"
