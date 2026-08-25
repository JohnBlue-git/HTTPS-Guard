#!/usr/bin/env python3
"""Drive HTTPS-Guard's detections on a QEMU (or real) BMC, one case per run.

Covers seven of the nine detections. Two are deliberately absent and say so
under --list: cert_access cannot fire at all on ARM32 (no BPF trampoline), and
traffic_observed needs no help — every clean request produces it.

WHERE EACH CASE HAS TO RUN, AND WHY
===================================

Read this before wondering why one case shells into the guest and the rest do
not. It is not inconsistency; the two groups are excited from opposite sides.

FROM THE HOST — everything fed by XDP
    XDP sits on the BMC's NIC receive path, so it only ever sees traffic that
    arrived over the wire. Traffic the guest originates to its own 127.0.0.1
    never traverses XDP at all, so running these inside the guest would do
    nothing, silently. They must come from outside.

    That covers the ClientHello cases (a hand-built record is the only way to
    offer RC4 or TLS 1.0 — OpenSSL 3.x refuses to, and `curl --tlsv1.0` is
    silently ignored) and the three volumetric cases, which are counted per
    source address at the same point in the packet path.

FROM INSIDE THE GUEST, over SSH — payload_anomaly
    This one is fed by uprobes on OpenSSL, which fire for any process on the
    BMC calling SSL_write/SSL_read. It needs a *completed* TLS handshake so
    plaintext actually passes through those calls, which a hand-built record
    cannot produce — that would mean implementing a TLS client here.

    It could be excited from the host with a real HTTPS request, and the
    detection would fire. We do not, for two concrete reasons:

    1. The enforcing half cannot be demonstrated that way. From the host the
       only uprobe event is bmcweb's SSL_read of the request. During a live
       request bmcweb's own file descriptors are unix-domain and listening
       sockets rather than an established TCP socket, so ProcPeerResolver
       fails closed and logs "peer unresolved"; enforcement declines. You see
       the Redfish event and never the teardown. Run in-guest, `openssl
       s_client` is a client process owning exactly one established
       connection, so the tuple resolves and SOCK_DESTROY has something to
       act on.

    2. If it *did* resolve, it would lock you out. The blocklist applies to a
       source address on every port, not just 443 — so a verdict against your
       own machine takes SSH and Redfish with it for the TTL (300s). Run
       in-guest, the peer is 127.0.0.1, and loopback never traverses XDP, so
       the blocklist entry is inert. That makes this the one *enforcing*
       detection that is safe to trigger repeatedly.

THE THREE VOLUMETRIC CASES ENFORCE, AND WILL LOCK YOU OUT
=========================================================
conn_rate, slowloris and renegotiation all blocklist the source once they fire
— and run from the host, that source is you. Expect to lose SSH and Redfish for
the blocklist TTL. That is the detection working, not a bug.

Their shipped thresholds (500 connections / 100 held open / 200 handshakes per
10s window) are hard-to-impossible to reach through a QEMU SLIRP port-forward.
What each one actually does through SLIRP, measured on this project's QEMU:

    conn_rate    -- works. Each completed connection is a fresh SYN to the
                    guest, so the windowed attempt counter accumulates. Lower
                    HTTPS_GUARD_RATE_THRESHOLD to see it cross.
    renegotiation-- works at a low threshold. bmcweb RSTs the malformed record
                    stream after ~3 records, so one connection delivers ~3
                    countable 0x16 records regardless of --count. Fires with
                    HTTPS_GUARD_RENEG_THRESHOLD=2; does not at 6.
    slowloris    -- unreliable through a SLIRP hostfwd. An earlier run reached
                    5 held connections, but a re-measurement saw only ~1 of 3-8
                    arrive as guest-side open_conns -- SLIRP does not forward
                    held host connections to the guest consistently. Needs a
                    real netdev or bridged/TAP network to be dependable. See
                    run_slowloris.

Lower the relevant HTTPS_GUARD_*_THRESHOLD in /etc/default/https-guard and
restart the daemon to see conn_rate/renegotiation cross the line. --list says
which threshold each case drives.
"""

import argparse
import shutil
import socket
import struct
import subprocess
import sys
import time


# --------------------------------------------------------------------------
# ClientHello construction
# --------------------------------------------------------------------------

def u16(v):
    return struct.pack("!H", v)


def client_hello(suites, sni=None, name_type=0, bad_name_len=None,
                 legacy_version=0x0303):
    """One TLS ClientHello record.

    legacy_version is the field the TLS-version detection reads on the XDP
    path. name_type != 0 makes the SNI entry unparseable, which is what the SNI
    detection flags as malformed; bad_name_len overstates the hostname length,
    which truncates the captured name.
    """
    body = u16(legacy_version) + b"\xAB" * 32 + b"\x00"   # version, random, no session id
    body += u16(len(suites) * 2) + b"".join(u16(s) for s in suites)
    body += b"\x01\x00"                                   # 1 compression method, null

    exts = b""
    if sni is not None:
        host = sni.encode()
        nlen = bad_name_len if bad_name_len is not None else len(host)
        sni_body = u16(nlen + 3) + bytes([name_type]) + u16(nlen) + host
        exts += u16(0x0000) + u16(len(sni_body)) + sni_body
    body += u16(len(exts)) + exts

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + u16(len(handshake)) + handshake


def send_record(host, port, record, timeout=5):
    """Send one record and close. No handshake completes, and none needs to:
    XDP inspects the first record on the wire."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.send(record)
        try:
            sock.recv(64)   # the server will reject it; we do not care what it says
        except OSError:
            pass
    finally:
        sock.close()


# --------------------------------------------------------------------------
# Case runners
# --------------------------------------------------------------------------

def run_client_hello(args, record):
    send_record(args.host, args.port, record)
    print(f"sent 1 ClientHello ({len(record)} bytes) to {args.host}:{args.port}")


def run_conn_rate(args):
    """Completed connections, counted per source at the XDP hook.

    Completed, not a SYN burst: QEMU SLIRP terminates and re-originates TCP, so
    a rapid connect/reset burst from the host does not arrive at the guest as
    SYNs at all. This was measured -- ~456 completed connections in 6s was the
    ceiling reachable this way, just under the shipped 500 threshold.
    """
    ok = err = 0
    for _ in range(args.count):
        try:
            socket.create_connection((args.host, args.port), timeout=2).close()
            ok += 1
        except OSError:
            err += 1
        time.sleep(args.interval)
    print(f"completed {ok} connection(s) ({err} failed) to {args.host}:{args.port}")
    print(f"expect: syn_count += {ok} for this source, against "
          f"HTTPS_GUARD_RATE_THRESHOLD (shipped default 500 per 10s window)")


def run_slowloris(args):
    """Open connections and hold them, which is the whole attack.

    The counter behind this is a LEVEL, not a windowed rate: it survives the
    window roll, because an attacker who opens connections and then goes quiet
    would otherwise look idle -- which is exactly what the attack engineers.

    SLIRP CAVEAT, and it is a sharp one -- two parts:

      - Unreliable through a SLIRP hostfwd. An earlier run (see the ticket 06
        record under .scratch/) reached open_conns=5 with a limit of 3 and
        fired; but a later re-measurement in the same SLIRP setup saw only ~1
        of 3-8 held host connections arrive as guest-side open_conns -- holding
        8 produced 0 open_conns and just 1 SYN at the guest. SLIRP does not
        forward held host connections to the guest consistently, and how many
        arrive is environment/timing/version-dependent. Do not rely on this
        through SLIRP; use a real netdev or a bridged/TAP network.
      - Holding as few as five connections through a QEMU hostfwd saturates the
        forward and breaks SSH on that same forward. If you lose the shell,
        that is the forward, not the blocklist -- the two are indistinguishable
        from out here. Read the guest's journal.
    """
    held = []
    try:
        for _ in range(args.count):
            try:
                s = socket.create_connection((args.host, args.port), timeout=2)
                held.append(s)
            except OSError:
                break
        print(f"holding {len(held)} connection(s) open for {args.hold}s")
        print(f"expect: open_conns == {len(held)} for this source, against "
              f"HTTPS_GUARD_SLOWLORIS_THRESHOLD (shipped default 100)")
        time.sleep(args.hold)
    finally:
        for s in held:
            try:
                s.close()
            except OSError:
                pass
        print(f"released {len(held)} connection(s)")


def run_renegotiation(args):
    """Repeated TLS handshake records down ONE connection.

    A renegotiation storm is many handshakes on a single connection, so that
    is what this sends: one socket, --count handshake records (ContentType
    0x16) written back to back. The XDP counter increments on any 0x16 record
    regardless of connection, so it does not care that no handshake completes --
    but keeping them on one connection matters for two reasons:

      1. It is what the attack actually is. One-socket-per-record would be a
         connection-rate flood wearing a renegotiation costume.
      2. SLIRP. QEMU's user-mode network re-originates every TCP connection,
         and drops some under a burst -- 8 separate connections delivered only
         5 records, measured. One established connection is re-originated once
         and then every record rides it, so all --count arrive.

    TCP_NODELAY plus a short inter-record sleep keeps Nagle from coalescing the
    records into one segment; XDP only reads the first payload byte of each
    segment, so coalesced records would count once, not N times.
    """
    record = client_hello([0x1301, 0x1302, 0xC030], sni="bmc.example.com")
    sent = 0
    sock = socket.create_connection((args.host, args.port), timeout=5)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for _ in range(args.count):
            try:
                sock.sendall(record)
                sent += 1
            except OSError:
                # The server may RST after a malformed record; the ones already
                # on the wire were counted by XDP on ingress regardless.
                break
            time.sleep(args.interval)
    finally:
        sock.close()
    print(f"sent {sent} handshake record(s) on one connection to "
          f"{args.host}:{args.port}")
    print(f"expect: hello_count += {sent} for this source, against "
          f"HTTPS_GUARD_RENEG_THRESHOLD (per 10s window)")
    print("note: bmcweb RSTs the malformed stream after ~3 records, so this "
          "delivers ~3 through SLIRP regardless of --count. To see it fire, set "
          "HTTPS_GUARD_RENEG_THRESHOLD below that (measured: 2 fires, 6 does "
          "not). The shipped default of 200 is not reachable from this script.")


def run_payload_anomaly(args):
    """The one case that runs INSIDE the guest -- see the module docstring.

    Sends an attack signature through a real TLS session, held open long enough
    for enforcement to have a live socket to tear down. The signature goes in
    the request path rather than a header, because capture is capped at 127
    bytes per SSL_read and a signature past that offset is not seen.
    """
    remote = (
        "(printf 'GET /etc/passwd HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n'; "
        f"sleep {args.hold}) | openssl s_client -connect 127.0.0.1:443 -quiet -ign_eof "
        ">/dev/null 2>&1 & sleep 6; wait"
    )

    ssh = ["ssh", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=5",
           "-p", str(args.ssh_port), f"{args.ssh_user}@{args.host}", remote]

    if args.ssh_pass:
        if not shutil.which("sshpass"):
            print("error: --ssh-pass given but sshpass is not installed; "
                  "use key auth or install sshpass", file=sys.stderr)
            return 2
        ssh = ["sshpass", "-p", args.ssh_pass] + ssh

    print(f"running openssl in-guest via ssh {args.ssh_user}@{args.host}:{args.ssh_port}")
    result = subprocess.run(ssh, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ssh exited {result.returncode}: {result.stderr.strip()}", file=sys.stderr)
        return 1

    print("expect, in the guest's journal:")
    print("  claimed by 'payload_anomaly' ... HttpsPayloadAnomalyDetected")
    print("  BlockTcpAction: destroyed TCP connection 127.0.0.1:... -> 127.0.0.1:443")
    print("  BlocklistAddAction: blocklisted 127.0.0.1 for 300s")
    print("note: a second event for bmcweb's own SSL_read usually declines to")
    print("      enforce ('peer unresolved') -- that is expected, see LIMITATIONS.md")
    return 0


# --------------------------------------------------------------------------
# Case table
# --------------------------------------------------------------------------
# (name, where it runs, what it should trigger, runner)
CASES = {
    # ---- ClientHello, from the host -------------------------------------
    "clean": ("host", "nothing — the control case; expect HttpsTrafficObserved",
              lambda a: run_client_hello(a, client_hello(
                  [0x1301, 0x1302, 0xC030], sni="bmc.example.com"))),
    "weak_rc4": ("host", "HttpsWeakCipherSuiteDetected — RC4 (0x0005) among modern suites",
                 lambda a: run_client_hello(a, client_hello(
                     [0x1301, 0x0005, 0xC02F], sni="bmc.example.com"))),
    "weak_3des": ("host", "HttpsWeakCipherSuiteDetected — 3DES (0x000A)",
                  lambda a: run_client_hello(a, client_hello(
                      [0x1301, 0x000A], sni="bmc.example.com"))),
    "weak_null": ("host", "HttpsWeakCipherSuiteDetected — NULL encryption (0x0002)",
                  lambda a: run_client_hello(a, client_hello(
                      [0x0002], sni="bmc.example.com"))),
    "bad_sni": ("host", "HttpsSniAnomalyDetected — unknown SNI name_type",
                lambda a: run_client_hello(a, client_hello(
                    [0x1301], sni="bmc.example.com", name_type=7))),
    "truncated_sni": ("host", "HttpsSniAnomalyDetected — declared name length exceeds the record",
                      lambda a: run_client_hello(a, client_hello(
                          [0x1301], sni="bmc.example.com", bad_name_len=200))),
    "other_sni": ("host", "HttpsSniAnomalyDetected, ONLY if HTTPS_GUARD_EXPECTED_SNI is set to something else",
                  lambda a: run_client_hello(a, client_hello(
                      [0x1301], sni="attacker.example.net"))),
    "legacy_tls10": ("host", "HttpsTlsVersionViolation — legacy_version 0x0301. ENFORCES: blocklists you",
                     lambda a: run_client_hello(a, client_hello(
                         [0x1301], sni="bmc.example.com", legacy_version=0x0301))),

    # ---- volumetric, from the host --------------------------------------
    "conn_rate": ("host", "HttpsConnectionRateViolation — --count completed connections. ENFORCES",
                  run_conn_rate),
    "slowloris": ("host", "HttpsSlowlorisDetected — connections held open. ENFORCES. "
                          "Unreliable through SLIRP (~1 of 3-8 held reach the guest); needs real netdev/TAP",
                  run_slowloris),
    "renegotiation": ("host", "HttpsTlsRenegotiationStorm — 0x16 records on one connection. "
                              "ENFORCES. SLIRP delivers ~3 before bmcweb RST; set threshold below that",
                      run_renegotiation),

    # ---- uprobe, from inside the guest ----------------------------------
    "payload_anomaly": ("guest (ssh)", "HttpsPayloadAnomalyDetected + a real teardown. ENFORCES, but safely",
                        run_payload_anomaly),
}

UNREACHABLE = {
    "cert_access": "cannot fire on ARM32 — BPF-LSM attach needs a trampoline this "
                   "architecture has never implemented. See detections/cert_access/DESIGN.md",
    "traffic_observed": "needs no trigger — any clean request produces it; `clean` above shows it",
}


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", nargs="?", help="which detection to drive")
    ap.add_argument("--host", default="127.0.0.1",
                    help="BMC address, or the host side of a QEMU port forward")
    ap.add_argument("--port", type=int, default=443,
                    help="443 direct, or the forwarded HTTPS port under SLIRP (often 4433+)")
    ap.add_argument("--count", type=int, default=150,
                    help="connections or records, for the volumetric cases")
    ap.add_argument("--interval", type=float, default=0.02,
                    help="seconds between connections/records")
    ap.add_argument("--hold", type=int, default=20,
                    help="seconds to hold connections open (slowloris), or to keep "
                         "the TLS session alive (payload_anomaly)")
    ap.add_argument("--ssh-port", type=int, default=2222,
                    help="forwarded SSH port, for the in-guest case")
    ap.add_argument("--ssh-user", default="root")
    ap.add_argument("--ssh-pass", default=None,
                    help="password for the in-guest case (QEMU test images only; "
                         "omit to use key auth)")
    ap.add_argument("--list", action="store_true", help="list cases and what each drives")
    args = ap.parse_args()

    if args.list or not args.case:
        width = max(len(k) for k in CASES)
        print("Run from the HOST (fed by XDP — the guest's own loopback never traverses it):")
        for name, (where, what, _) in CASES.items():
            if where == "host":
                print(f"  {name:<{width}}  {what}")
        print("\nRun INSIDE the guest over SSH (fed by uprobes — see --help for why):")
        for name, (where, what, _) in CASES.items():
            if where != "host":
                print(f"  {name:<{width}}  {what}")
        print("\nNot triggerable here:")
        for name, why in UNREACHABLE.items():
            print(f"  {name:<{width}}  {why}")
        print("\nEverything marked ENFORCES blocklists the source for the TTL. From the")
        print("host that source is you — expect to lose SSH. payload_anomaly is the")
        print("exception: its peer is the guest's own loopback, so it is safe to repeat.")
        return 0

    if args.case not in CASES:
        hint = UNREACHABLE.get(args.case)
        if hint:
            print(f"'{args.case}' is not triggerable: {hint}", file=sys.stderr)
            return 2
        print(f"unknown case '{args.case}'; try --list", file=sys.stderr)
        return 2

    where, what, runner = CASES[args.case]
    print(f"case: {args.case}  (runs from the {where})")
    print(f"expect: {what}")
    rc = runner(args)
    return rc if isinstance(rc, int) else 0


if __name__ == "__main__":
    sys.exit(main())
