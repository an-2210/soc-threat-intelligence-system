"""Tiny stand-in for Part 3's POST /alert endpoint. Run it, then point detector.py at it."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

REQUIRED = ["timestamp", "source", "src_ip", "dst_ip", "dst_port", "label", "confidence", "top_features"]
LABELS = {"BruteForce", "DoS", "PortScan", "Anomaly"}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/alert":
            self.send_response(404); self.end_headers(); return
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        problems = [k for k in REQUIRED if k not in data]
        if data.get("label") not in LABELS:
            problems.append("bad label: %s" % data.get("label"))
        print("OK     " if not problems else "PROBLEM", data if not problems else problems)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')
    def log_message(self, *args):
        pass

print("Listening on port 8000 ...")
HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
