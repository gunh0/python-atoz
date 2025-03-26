"""TCP health check — tell "refused", "timeout" and "no such host" apart

"Port 22 is down" is not one failure but several, and each one sends you to
a different place: connection refused means the host is up but nothing
listens (service crashed), a timeout means packets vanish or the service is
hung (firewall, overload), and a name resolution failure means DNS or a typo
in the inventory. A health check that prints only "DOWN" throws that
information away. This one connects with a timeout, reads the banner the
service sends, and maps each exception class to a precise status.

Everything runs against small threaded servers on 127.0.0.1 started by the
script itself; ports are random and never printed. "host.invalid" uses the
reserved .invalid TLD (RFC 2606), so it can never resolve.
"""

import socket
import socketserver
import threading
from dataclasses import dataclass


class BannerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(self.server.banner)


class HungHandler(socketserver.BaseRequestHandler):
    """Accepts the connection, then never answers (a wedged service)."""

    def handle(self) -> None:
        self.server.release.wait(timeout=5)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, handler, banner: bytes = b""):
        super().__init__(("127.0.0.1", 0), handler)
        self.banner = banner
        self.release = threading.Event()
        threading.Thread(target=self.serve_forever, args=(0.05,), daemon=True).start()

    def stop(self) -> None:
        self.release.set()
        self.shutdown()
        self.server_close()


def closed_port() -> int:
    """A port with nothing listening: bind to get a free one, then close it."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Result:
    name: str
    status: str
    detail: str


def check(name: str, host: str, port: int, expect: bytes, timeout: float = 0.5) -> Result:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)  # the same budget for the banner read
            banner = sock.recv(256)
    except socket.gaierror:
        return Result(name, "DNS", "name does not resolve")
    except ConnectionRefusedError:
        return Result(name, "REFUSED", "host up, nothing listening")
    except TimeoutError:
        return Result(name, "TIMEOUT", f"no answer within {timeout}s")
    except OSError as exc:  # unreachable network, reset, ...
        return Result(name, "ERROR", type(exc).__name__)
    text = banner.decode("ascii", "replace").strip()
    if not banner:
        return Result(name, "CLOSED", "connected, peer closed without banner")
    if not banner.startswith(expect):
        return Result(name, "BAD", f"unexpected banner {text!r}")
    return Result(name, "OK", text)


def main() -> None:
    healthy = Server(BannerHandler, b"OK app 2.4.1\n")
    degraded = Server(BannerHandler, b"ERR maintenance\n")
    hung = Server(HungHandler)
    try:
        targets = [
            ("app", "127.0.0.1", healthy.server_address[1]),
            ("app-canary", "127.0.0.1", degraded.server_address[1]),
            ("queue", "127.0.0.1", hung.server_address[1]),
            ("cache", "127.0.0.1", closed_port()),
            ("legacy", "host.invalid", 80),
        ]
        results = [check(name, host, port, expect=b"OK") for name, host, port in targets]
    finally:
        for server in (healthy, degraded, hung):
            server.stop()

    for r in results:
        print(f"{r.name:<11} {r.status:<8} {r.detail}")
    bad = [r.name for r in results if r.status != "OK"]
    print(f"{len(results) - len(bad)}/{len(results)} healthy; page on-call for: {', '.join(bad)}")


if __name__ == "__main__":
    main()

# Output:
# app         OK       OK app 2.4.1
# app-canary  BAD      unexpected banner 'ERR maintenance'
# queue       TIMEOUT  no answer within 0.5s
# cache       REFUSED  host up, nothing listening
# legacy      DNS      name does not resolve
# 1/5 healthy; page on-call for: app-canary, queue, cache, legacy
