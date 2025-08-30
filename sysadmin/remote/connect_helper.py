"""connect_helper, first fix — narrow except, close the socket, still lossy

The first round of review on the original helper fixed the two loud bugs:

- `except:` became `except OSError`, the base class of every socket error.
  Anything else now reaches the caller with its real type: a port that
  answers with a binary MySQL handshake raises UnicodeDecodeError instead
  of being reported as "connection error".
- socket.create_connection() inside `with` closes the socket on every path,
  and it tries each address DNS returns (IPv6 and IPv4) instead of AF_INET
  only. The ResourceWarnings are gone.

It also tried to report the reason, by adding handlers for TimeoutError and
socket.gaierror. They never run: TimeoutError and gaierror are subclasses of
OSError, and the first matching `except` clause wins, so the specific
handlers below the general one are dead code. Linters flag this; the code
still "works", which is why it survives. The function also still returns
None, so every caller has to remember to check. Both are fixed next.
"""

import gc
import socket
import warnings

from _testservers import local_servers


def connect(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return sock.recv(64).decode("ascii").strip()
    except OSError:
        print("    network error")
    except TimeoutError:  # unreachable: TimeoutError is an OSError
        print("    timed out")
    except socket.gaierror:  # unreachable: gaierror is an OSError
        print("    cannot resolve host")
    return None


def caller(host, port) -> str:
    try:
        banner = connect(host, port)
    except UnicodeDecodeError as exc:
        return f"caller sees the real problem: UnicodeDecodeError: {exc.reason} at byte {exc.start}"
    if banner is None:  # every caller must remember this check
        return "failed (reason unknown to the caller)"
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
                print(f"{label}:")
                print(f"    -> {caller(host, port)}")
            gc.collect()
    leaks = [w for w in caught if issubclass(w.category, ResourceWarning)]
    print(f"unclosed sockets reported: {len(leaks)}")
    for exc_type in (TimeoutError, socket.gaierror, ConnectionRefusedError):
        print(f"{exc_type.__name__} is an OSError: {issubclass(exc_type, OSError)}")


if __name__ == "__main__":
    main()

# Output:
# healthy:
#     -> banner 'OK app 2.4.1'
# hung service:
#     network error
#     -> failed (reason unknown to the caller)
# refused:
#     network error
#     -> failed (reason unknown to the caller)
# dns failure:
#     network error
#     -> failed (reason unknown to the caller)
# binary protocol:
#     -> caller sees the real problem: UnicodeDecodeError: ordinal not in range(128) at byte 16
# unclosed sockets reported: 0
# TimeoutError is an OSError: True
# gaierror is an OSError: True
# ConnectionRefusedError is an OSError: True
