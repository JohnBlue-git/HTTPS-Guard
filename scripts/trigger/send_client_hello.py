#!/usr/bin/env python3
"""Send a hand-built TLS ClientHello, to exercise the XDP-fed detection rules.

Why this exists: the rules that read ClientHello bytes (weak cipher suites,
SNI anomalies, legacy TLS versions) cannot be driven with a normal client.
OpenSSL 3.x refuses to *offer* the things they look for -- `curl --tlsv1.0`
is silently ignored, and no modern library will put RC4 in its suite list.
So the handshake has to be built by hand.

Nothing here completes a handshake: the XDP program inspects the first
record on the wire, so sending that one record and closing is enough.

Run it from OUTSIDE the guest. Traffic the guest originates to 127.0.0.1
never traverses XDP, so a case run on the BMC itself will silently do
nothing.

  ./send_client_hello.py --list
  ./send_client_hello.py weak_rc4 --host 127.0.0.1 --port 4434
"""

import argparse
import socket
import struct
import sys


def u16(v):
    return struct.pack("!H", v)


def client_hello(suites, sni=None, name_type=0, bad_name_len=None,
                 legacy_version=0x0303):
    """One TLS ClientHello record.

    legacy_version is the field TlsVersionDetector reads on the XDP path.
    name_type != 0 makes the SNI entry unparseable, which is what
    SniDetector flags as malformed; bad_name_len overstates the hostname
    length, which truncates the captured name.
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


# label -> (record, what it should trigger)
CASES = {
    "weak_rc4": (
        client_hello([0x1301, 0x0005, 0xC02F], sni="bmc.example.com"),
        "HttpsWeakCipherSuiteDetected -- RC4 (0x0005) offered alongside modern suites",
    ),
    "weak_3des": (
        client_hello([0x1301, 0x000A], sni="bmc.example.com"),
        "HttpsWeakCipherSuiteDetected -- 3DES (0x000A)",
    ),
    "weak_null": (
        client_hello([0x0002], sni="bmc.example.com"),
        "HttpsWeakCipherSuiteDetected -- NULL encryption (0x0002)",
    ),
    "bad_sni": (
        client_hello([0x1301], sni="bmc.example.com", name_type=7),
        "HttpsSniAnomalyDetected -- unknown SNI name_type, so the name is unparseable",
    ),
    "truncated_sni": (
        client_hello([0x1301], sni="bmc.example.com", bad_name_len=200),
        "HttpsSniAnomalyDetected -- declared hostname length exceeds the record",
    ),
    "other_sni": (
        client_hello([0x1301], sni="attacker.example.net"),
        "HttpsSniAnomalyDetected, but ONLY if HTTPS_GUARD_EXPECTED_SNI is set to something else",
    ),
    "legacy_tls10": (
        client_hello([0x1301], sni="bmc.example.com", legacy_version=0x0301),
        "HttpsTlsVersionViolation -- legacy_version 0x0301 (TLS 1.0). ENFORCES: blocklists the source",
    ),
    "clean": (
        client_hello([0x1301, 0x1302, 0xC030], sni="bmc.example.com"),
        "nothing -- the control case. Should produce no violation",
    ),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", nargs="?", help="which ClientHello to send")
    ap.add_argument("--host", default="127.0.0.1",
                    help="BMC address, or the host side of a QEMU port forward")
    ap.add_argument("--port", type=int, default=443,
                    help="443 direct, or the forwarded port under QEMU SLIRP (often 4433/4434)")
    ap.add_argument("--list", action="store_true", help="list cases and what each should trigger")
    args = ap.parse_args()

    if args.list or not args.case:
        width = max(len(k) for k in CASES)
        for label, (_, what) in CASES.items():
            print(f"  {label:<{width}}  {what}")
        return 0

    if args.case not in CASES:
        print(f"unknown case '{args.case}'; try --list", file=sys.stderr)
        return 2

    record, what = CASES[args.case]
    sock = socket.create_connection((args.host, args.port), timeout=5)
    sock.send(record)
    try:
        sock.recv(64)      # the server will reject it; we do not care what it says
    except OSError:
        pass
    sock.close()
    print(f"sent {args.case} ({len(record)} bytes) to {args.host}:{args.port}")
    print(f"expect: {what}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
