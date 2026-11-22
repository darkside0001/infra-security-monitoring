"""Minimal Alertmanager webhook receiver for the lab.

Prints one JSON line per alert, so notifications end up in Loki like any
other container log and verify.sh can check that delivery works.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = min(int(self.headers.get("Content-Length", 0)), 1_000_000)
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return
        for a in body.get("alerts", []):
            print(json.dumps({
                "event": "alert_notification",
                "status": a.get("status"),
                "alertname": a.get("labels", {}).get("alertname"),
                "severity": a.get("labels", {}).get("severity"),
                "summary": a.get("annotations", {}).get("summary"),
                "startsAt": a.get("startsAt"),
            }))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
