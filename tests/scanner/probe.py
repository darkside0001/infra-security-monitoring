"""External checks against the stack, run from the edge network.

Prints one JSON object per check: {"id", "name", "ok", "evidence"}.
Only targets the lab hosts (crm.lab.test / grafana.lab.test on 172.28.10.10).
"""

import http.client
import json
import socket
import ssl
import sys
import time

EDGE_IP = "172.28.10.10"
CA = "/lab-ca.crt"
CRM = "crm.lab.test"
GRAFANA = "grafana.lab.test"
results = []


def check(cid, name, ok, evidence):
    results.append({"id": cid, "name": name, "ok": bool(ok), "evidence": evidence})


def ctx(min_v=None, max_v=None):
    c = ssl.create_default_context(cafile=CA)
    if min_v:
        c.minimum_version = min_v
    if max_v:
        c.maximum_version = max_v
    return c


def tls_handshake(host, c):
    with socket.create_connection((EDGE_IP, 443), timeout=5) as s:
        with c.wrap_socket(s, server_hostname=host) as t:
            return t.version(), t.cipher()[0]


def https(host, method, path, body=None, headers=None):
    conn = http.client.HTTPSConnection(EDGE_IP, 443, context=ctx(), timeout=10)
    h = {"Host": host, **(headers or {})}
    # SNI must be the lab hostname, not the IP.
    conn.sock = ctx().wrap_socket(socket.create_connection((EDGE_IP, 443), timeout=10), server_hostname=host)
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, data


# --- TLS ---------------------------------------------------------------
for label, v in (("1.3", ssl.TLSVersion.TLSv1_3), ("1.2", ssl.TLSVersion.TLSv1_2)):
    try:
        ver, cipher = tls_handshake(CRM, ctx(v, v))
        check(f"TLS-{label}", f"TLS {label} accepted", True, f"{ver} {cipher}")
    except Exception as e:  # noqa: BLE001
        check(f"TLS-{label}", f"TLS {label} accepted", False, repr(e))

for label, v in (("1.1", ssl.TLSVersion.TLSv1_1), ("1.0", ssl.TLSVersion.TLSv1)):
    c = ctx(v, v)
    c.set_ciphers("DEFAULT:@SECLEVEL=0")
    try:
        ver, _ = tls_handshake(CRM, c)
        check(f"TLS-{label}", f"TLS {label} rejected", False, f"server accepted {ver}")
    except (ssl.SSLError, OSError) as e:
        check(f"TLS-{label}", f"TLS {label} rejected", True, type(e).__name__ + ": " + str(e)[:120])

try:
    c = ssl.create_default_context()  # system CAs only: the lab CA must not be trusted
    tls_handshake(CRM, c)
    check("TLS-CHAIN", "Unknown CA is rejected by a default client", False, "handshake succeeded")
except ssl.SSLCertVerificationError as e:
    check("TLS-CHAIN", "Unknown CA is rejected by a default client", True, e.verify_message)

# --- HTTP --------------------------------------------------------------
conn = http.client.HTTPConnection(EDGE_IP, 80, timeout=5)
conn.request("GET", "/api/v1/products", headers={"Host": CRM})
r = conn.getresponse()
check("HTTP-REDIRECT", "Plain HTTP redirects to HTTPS", r.status in (301, 308) and r.getheader("Location", "").startswith("https://"),
      f"{r.status} Location: {r.getheader('Location')}")

status, h, _ = https(CRM, "GET", "/health")
want = {
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'none'",
    "referrer-policy": "no-referrer",
}
missing = [k for k, v in want.items() if v not in h.get(k, "")]
check("HDR-SECURITY", "Security headers present", status == 200 and not missing, f"status {status}, missing: {missing or 'none'}")
check("HDR-BANNER", "No Server / X-Powered-By banner", "server" not in h and "x-powered-by" not in h,
      f"server={h.get('server')!r} x-powered-by={h.get('x-powered-by')!r}")

for path in ("/docs", "/openapi.json"):
    status, _, _ = https(CRM, "GET", path)
    check(f"PATH-{path}", f"{path} not exposed", status == 404, f"status {status}")

status, _, _ = https(CRM, "POST", "/api/v1/auth/login", body=b"x" * 2_000_000, headers={"Content-Type": "application/json"})
check("BODY-LIMIT", "Request body over 1 MB rejected", status == 413, f"status {status}")

status, _, _ = https(CRM, "GET", "/api/v1/customers")
check("AUTHZ-NOTOKEN", "API refuses requests without a token", status == 401, f"status {status}")

status, h, _ = https(GRAFANA, "GET", "/api/search")
check("GRAFANA-AUTH", "Grafana API requires login (no anonymous access)", status == 401, f"status {status}")

# --- Attack simulation (feeds the log-based detections) -----------------
codes = []
for i in range(15):
    body = json.dumps({"email": "admin@example.com", "password": f"wrong-password-{i}"}).encode()
    # A spoofed X-Forwarded-For must not change the address the app and logs see.
    status, _, _ = https(CRM, "POST", "/api/v1/auth/login", body=body,
                         headers={"Content-Type": "application/json", "X-Forwarded-For": f"203.0.113.{i}"})
    codes.append(status)
throttled = [c for c in codes if c in (423, 429)]
check("BRUTE-THROTTLE", "Repeated failed logins get throttled (429/423)", len(throttled) > 0,
      f"status codes: {codes}")

probe_codes = []
for path in ("/.env", "/.git/config", "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/actuator/env", "/server-status"):
    status, _, _ = https(CRM, "GET", path)
    probe_codes.append(status)
check("PROBE-PATHS", "Sensitive-file probing returns nothing useful", all(c in (401, 403, 404) for c in probe_codes),
      f"status codes: {probe_codes}")

# --- Reachability: internal services must not be reachable from the edge ----
internal = {
    "PostgreSQL db:5432": ("172.28.30.0/24", 5432),
    "Prometheus :9090": ("172.28.40.0/24", 9090),
    "Loki :3100": ("172.28.40.0/24", 3100),
    "crm-api :8000": ("172.28.20.0/24", 8000),
}
for name, (net, port) in internal.items():
    base = net.rsplit(".", 1)[0]
    reached = []
    for last in range(2, 20):
        try:
            socket.create_connection((f"{base}.{last}", port), timeout=0.3).close()
            reached.append(f"{base}.{last}")
        except OSError:
            pass
    check(f"NET-{port}", f"{name} unreachable from the edge network", not reached, f"reachable: {reached or 'none'} (scanned {base}.2-19)")

for r in results:
    print(json.dumps(r))
sys.exit(0 if all(r["ok"] for r in results) else 1)
