"""A stand-in for an attacker's server. It only prints what it receives.

If anything shows up in this log during the demo, data has left the
guardrails. The goal is for it to stay silent.
"""

import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

RED, BOLD, RESET = "\033[31m", "\033[1m", "\033[0m"


class Handler(BaseHTTPRequestHandler):
    def _capture(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 65536)).decode(errors="replace") if length else ""
        ts = dt.datetime.now().strftime("%H:%M:%S")
        print(f"{RED}{BOLD}{ts} 🚨 EXFILTRATION RECEIVED{RESET} {self.command} {unquote(self.path)[:400]}", flush=True)
        if body:
            print(f"{RED}         body: {body[:400]}{RESET}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"thanks for the data\n")

    do_GET = do_POST = do_PUT = _capture

    def log_message(self, *args) -> None:  # silence default access log
        pass


if __name__ == "__main__":
    print("attacker listener on :9999 (waiting... silence is good)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 9999), Handler).serve_forever()
