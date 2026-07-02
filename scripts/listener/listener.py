import base64
import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        print(f"\n[EVENT RECEIVED] Path: {self.path}", flush=True)
        print(body.decode('utf-8'), flush=True)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Success")

# Configuration
BMC_HOST = os.environ.get("BMC_HOST", "192.168.200.2")
BMC_USER = os.environ.get("BMC_USER", "root")
BMC_PASS = os.environ.get("BMC_PASS", "0penBmc")
LISTENER_PORT = int(os.environ.get("LISTENER_PORT", "8443"))
LISTENER_IP = os.environ.get("LISTENER_IP")

server_address = ('0.0.0.0', LISTENER_PORT)
httpd = HTTPServer(server_address, Handler)

# SSL Setup
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# Since we generated separate files in Step 1:
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

def detect_listener_ip():
    """Find the local IP the BMC would use to reach us, without sending
    any packets (UDP connect() just picks the outbound route/interface)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((BMC_HOST, 1))
        return s.getsockname()[0]
    finally:
        s.close()

def subscribe_to_bmc():
    """Register this listener as a Redfish EventService subscriber so
    Step 4 doesn't need a separate manual curl call."""
    listener_ip = LISTENER_IP or detect_listener_ip()
    destination = f"https://{listener_ip}:{LISTENER_PORT}/events"
    url = f"https://{BMC_HOST}/redfish/v1/EventService/Subscriptions"
    body = json.dumps({
        "Destination": destination,
        "Protocol": "Redfish",
    }).encode()

    creds = base64.b64encode(f"{BMC_USER}:{BMC_PASS}".encode()).decode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Basic {creds}",
    })

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            print(f"[SUBSCRIBE] {destination} -> HTTP {resp.status}", flush=True)
    except urllib.error.HTTPError as e:
        print(f"[SUBSCRIBE] failed: HTTP {e.code} {e.read().decode(errors='replace')}", flush=True)
    except (urllib.error.URLError, OSError) as e:
        print(f"[SUBSCRIBE] failed: {e}", flush=True)

subscribe_to_bmc()

print(f"Listener active on https://{server_address[0]}:{server_address[1]}/events", flush=True)
httpd.serve_forever()
