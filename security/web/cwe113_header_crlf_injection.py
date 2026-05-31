"""CWE-113: HTTP response splitting — CR/LF in a header value adds headers

https://cwe.mitre.org/data/definitions/113.html

A header line ends at CRLF. If a value taken from the request (a redirect
target, a filename for Content-Disposition, a language code) can contain
%0d%0a, the attacker writes their own header lines: Set-Cookie for session
fixation, a second Location, or an empty line followed by a body of their
choice.

Parts of the stdlib refuse such values (http.client.putheader, wsgiref
Headers, http.cookies and email.message all raise on these interpreters),
but http.server's BaseHTTPRequestHandler.send_header() writes whatever it is
given. The demo runs a real server on 127.0.0.1 and reads the response with
http.client. Validate every value that comes from outside: reject CR, LF and
other control characters (or encode them, e.g. percent-encode a URL), and
allow only token characters in header names.
"""

import http.client
import http.server
import re
import socketserver
import threading
from urllib.parse import parse_qs, urlsplit

CTL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")       # all controls except HTAB


class LocalServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """HTTPServer minus its server_bind(), which does a reverse DNS lookup (getfqdn)."""
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep stdout deterministic
        pass

    def do_GET(self):
        url = urlsplit(self.path)
        target = parse_qs(url.query).get("next", ["/"])[0]   # %0d%0a decoded to CR LF here
        if url.path == "/compliant/login" and CTL.search(target):
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(302)
        self.send_header("Location", target)                 # noncompliant on /login
        self.send_header("Content-Length", "0")
        self.end_headers()


def fetch(port: int, path: str) -> list[str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    resp.read()
    conn.close()
    lines = [f"status {resp.status}"]
    lines += [f"{k}: {v}" for k, v in resp.getheaders() if k in ("Location", "Set-Cookie")]
    return lines


def main() -> None:
    server = LocalServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    payload = "/home%0d%0aSet-Cookie:%20session=attacker-chosen;%20Path=/"
    try:
        for path in ("/login?next=/home", f"/login?next={payload}", f"/compliant/login?next={payload}"):
            print(f"GET {path}")
            for line in fetch(port, path):
                print(f"  {line}")
    finally:
        server.shutdown()
        server.server_close()

    print()
    conn = http.client.HTTPConnection("127.0.0.1", 9)       # never connects
    conn.putrequest("GET", "/")
    try:
        conn.putheader("X-Next", "/home\r\nSet-Cookie: s=1")
    except ValueError as exc:
        print(f"http.client.putheader refuses: {str(exc).split(' b')[0]}")


if __name__ == "__main__":
    main()

# Output:
# GET /login?next=/home
#   status 302
#   Location: /home
# GET /login?next=/home%0d%0aSet-Cookie:%20session=attacker-chosen;%20Path=/
#   status 302
#   Location: /home
#   Set-Cookie: session=attacker-chosen; Path=/
# GET /compliant/login?next=/home%0d%0aSet-Cookie:%20session=attacker-chosen;%20Path=/
#   status 400
#
# http.client.putheader refuses: Invalid header value
