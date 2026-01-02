"""connect_helper, second fix — specific handlers first, one exception type out

The first fix stopped the leaks and the swallowed bugs, but every network
failure was still "network error" and the function still returned None.
This version is the one to copy into other scripts:

- Handlers are ordered from most to least specific: gaierror, then
  ConnectionRefusedError, then TimeoutError, then OSError as the catch-all.
  Each one is now reachable.
- Failure is an exception, not None. Callers catch one type, ConnectError,
  which carries a machine-readable `reason` and a `transient` flag (worth a
  retry or not: a timeout may pass, a typo in the hostname will not).
- `raise ... from exc` keeps the original exception as __cause__, so the
  traceback still shows the errno and the OS message when someone needs it.
- A wrong protocol on the port is a ConnectError("protocol") rather than a
  UnicodeDecodeError, because for the caller it is "this is not the service
  I expected", not a bug in the code.

Ctrl-C (KeyboardInterrupt) and programming errors are still not caught.
"""

import gc
import socket
import warnings

from _testservers import local_servers


class ConnectError(Exception):
    def __init__(self, host: str, port: int, reason: str, transient: bool, detail: str = "") -> None:
        super().__init__(f"{host}:{port}: {reason}" + (f" ({detail})" if detail else ""))
        self.host, self.port = host, port
        self.reason, self.transient, self.detail = reason, transient, detail


def connect(host: str, port: int, timeout: float = 0.5, expect: bytes = b"OK") -> str:
    """Connect, read the banner and return it; raise ConnectError on failure."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            raw = sock.recv(64)
    except socket.gaierror as exc:
        raise ConnectError(host, port, "dns", transient=False) from exc
    except ConnectionRefusedError as exc:
        raise ConnectError(host, port, "refused", transient=True) from exc
    except TimeoutError as exc:
        raise ConnectError(host, port, "timeout", transient=True, detail=f"{timeout}s") from exc
    except OSError as exc:  # unreachable network, reset by peer, ...
        raise ConnectError(host, port, "network", transient=True, detail=type(exc).__name__) from exc
    if not raw.startswith(expect):
        raise ConnectError(host, port, "protocol", transient=False, detail=f"banner starts {raw[:5]!r}")
    return raw.decode("ascii", "replace").strip()


def caller(host: str, port: int) -> str:
    try:
        banner = connect(host, port)
    except ConnectError as err:
        action = "retry later" if err.transient else "fix config"
        cause = type(err.__cause__).__name__ if err.__cause__ else "-"
        detail = f" {err.detail}" if err.detail else ""
        return f"{err.reason}{detail}; cause={cause}; {action}"
    return f"banner {banner!r}"


def main() -> None:
    with local_servers() as srv:
        cases = [
            ("healthy", "127.0.0.1", srv.healthy),
            ("hung service", "127.0.0.1", srv.hung),
            ("refused", "127.0.0.1", srv.closed),
            ("dns failure", "host.invalid", 80),
            ("binary protocol", "127.0.0.1", srv.binary),
        ]
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            for label, host, port in cases:
                print(f"{label:<16} -> {caller(host, port)}")
            gc.collect()
    leaks = [w for w in caught if issubclass(w.category, ResourceWarning)]
    print(f"unclosed sockets reported: {len(leaks)}")
    err = ConnectError("db-01.example.net", 5432, "refused", transient=True)
    print(f"str(ConnectError) for logs: {err}")


if __name__ == "__main__":
    main()

# Output:
# healthy          -> banner 'OK app 2.4.1'
# hung service     -> timeout 0.5s; cause=TimeoutError; retry later
# refused          -> refused; cause=ConnectionRefusedError; retry later
# dns failure      -> dns; cause=gaierror; fix config
# binary protocol  -> protocol banner starts b'J\x00\x00\x00\n'; cause=-; fix config
# unclosed sockets reported: 0
# str(ConnectError) for logs: db-01.example.net:5432: refused
