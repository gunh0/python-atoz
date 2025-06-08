"""connect_helper, original version — the helper as it was first written

Every ops repo has a function like connect() below, copied between scripts:
open a socket, read the service banner, and on any problem print an error
and return None. It looks defensive. It is the reason a 3 a.m. incident
takes an hour instead of five minutes. This file keeps the original and
demonstrates what it actually does, so the next two commits can fix it:

1. The bare `except:` catches everything — a typo, a banner that is not
   text, even Ctrl-C (KeyboardInterrupt) — and reports all of it as
   "connection error". Refused, timeout, a DNS failure and "this port runs
   a different protocol" look identical.
2. It returns None on failure, so the caller crashes later with an unrelated
   TypeError ("cannot unpack non-iterable NoneType") far from the cause.
3. The socket is never closed on the error path; each failure leaks a file
   descriptor until the garbage collector runs (Python says so with a
   ResourceWarning, which is silent by default).
"""

import gc
import socket
import warnings

from _testservers import local_servers


def connect(host, port, timeout=0.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(64).decode("ascii").strip()
        return sock, banner
    except:  # noqa: E722 - this is the bug being demonstrated
        print("    connection error")
        return None


def caller(host, port) -> str:
    """Typical calling code: assumes success, as most callers do."""
    try:
        sock, banner = connect(host, port)
    except TypeError as exc:
        return f"caller crashed: TypeError: {exc}"
    with sock:
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


if __name__ == "__main__":
    main()

# Output:
# healthy:
#     -> banner 'OK app 2.4.1'
# hung service:
#     connection error
#     -> caller crashed: TypeError: cannot unpack non-iterable NoneType object
# refused:
#     connection error
#     -> caller crashed: TypeError: cannot unpack non-iterable NoneType object
# dns failure:
#     connection error
#     -> caller crashed: TypeError: cannot unpack non-iterable NoneType object
# binary protocol:
#     connection error
#     -> caller crashed: TypeError: cannot unpack non-iterable NoneType object
# unclosed sockets reported: 4
