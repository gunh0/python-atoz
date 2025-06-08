"""Throwaway TCP servers on 127.0.0.1 for the remote examples (not an example).

    with local_servers() as srv:
        srv.healthy  # port that sends b"OK app 2.4.1\\n"
        srv.hung     # port that accepts and never answers
        srv.binary   # port that greets with a binary (MySQL-style) handshake
        srv.closed   # port with nothing listening (connection refused)

Ports are picked by the OS; examples must never print them.
"""

import contextlib
import socket
import socketserver
import threading


class _BannerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(self.server.banner)


class _HungHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.release.wait(timeout=5)


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, handler, banner: bytes = b"") -> None:
        super().__init__(("127.0.0.1", 0), handler)
        self.banner = banner
        self.release = threading.Event()
        threading.Thread(target=self.serve_forever, args=(0.05,), daemon=True).start()

    @property
    def port(self) -> int:
        return self.server_address[1]

    def stop(self) -> None:
        self.release.set()
        self.shutdown()
        self.server_close()


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Start of a MySQL 8 server greeting: length, protocol 10, version, salt bytes.
MYSQL_GREETING = b"J\x00\x00\x00\n8.0.36\x00\x0b\x00\x00\x00\x9c\x1f\x7f\xd2\x05\x11\x3a\x41\x00"


class _Ports:
    def __init__(self, healthy: int, hung: int, binary: int, closed: int) -> None:
        self.healthy, self.hung, self.binary, self.closed = healthy, hung, binary, closed


@contextlib.contextmanager
def local_servers(banner: bytes = b"OK app 2.4.1\n"):
    healthy = _Server(_BannerHandler, banner)
    hung = _Server(_HungHandler)
    binary = _Server(_BannerHandler, MYSQL_GREETING)
    try:
        yield _Ports(healthy.port, hung.port, binary.port, closed_port())
    finally:
        for server in (healthy, hung, binary):
            server.stop()
