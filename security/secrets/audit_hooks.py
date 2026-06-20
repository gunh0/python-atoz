"""PEP 578 audit hooks — see which files, processes and sockets a dependency touches

https://peps.python.org/pep-0578/    (CWE-506: https://cwe.mitre.org/data/definitions/506.html)

When a new dependency or plugin is suspected of phoning home or reading
~/.aws/credentials, monkeypatching subprocess.Popen to watch it is the usual
first idea, and it misses os.system, os.posix_spawn and anything that kept a
reference to the original function. CPython raises an *audit event* inside
the runtime for each of these (open, subprocess.Popen, os.system,
os.posix_spawn, socket.connect, ...), and sys.addaudithook sees all of them.

A hook can also refuse an operation by raising, which is handy as a tripwire
in tests and build scripts ("this step must not open sockets"). It is not a
sandbox: hooks cannot be removed, but native code and ctypes can skip them.
Paths, ports and interpreter locations are trimmed so the output is stable.
"""

import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

WATCHED = {"open", "subprocess.Popen", "os.system", "os.posix_spawn", "socket.connect"}
seen: list[str] = []
recording = False


def summarize(event: str, args: tuple) -> str:
    if event == "open":
        return f"open {Path(str(args[0])).name} mode={args[1]}"
    if event == "subprocess.Popen":
        return f"subprocess.Popen argv[1:]={list(args[1][1:])}"
    if event == "os.posix_spawn":
        return f"os.posix_spawn argv[1:]={list(args[1][1:])}"
    if event == "os.system":
        return f"os.system {args[0].decode() if isinstance(args[0], bytes) else args[0]!r}"
    if event == "socket.connect":
        return f"socket.connect host={args[1][0]}"
    return event


def observer(event: str, args: tuple) -> None:
    if not recording or event not in WATCHED:
        return
    if event == "open" and str(args[0]).endswith((".py", ".pyc")):
        return  # lazy imports (idna for create_connection) also open files; skip module loads
    seen.append(summarize(event, args))


def no_outbound_network(event: str, args: tuple) -> None:
    if event == "socket.connect" and args[1][0] not in ("127.0.0.1", "::1"):
        raise PermissionError(f"blocked connect to {args[1][0]}")


class PopenSpy:
    """The noncompliant monitor: wrap subprocess.Popen and hope everyone uses it."""

    calls: list[str] = []

    def __init__(self, real):
        self.real = real

    def __call__(self, args, *a, **kw):
        PopenSpy.calls.append(f"Popen argv[1:]={list(args[1:])}")
        return self.real(args, *a, **kw)


def suspicious_plugin(workdir: Path, port: int) -> None:
    """Stands in for third-party code: reads a credentials file, spawns, connects."""
    (workdir / "credentials").read_text()
    # cwd= keeps subprocess on its fork/exec path; on recent glibc it may otherwise use
    # posix_spawn internally and raise an extra os.posix_spawn event on Linux only.
    subprocess.run([sys.executable, "-c", "pass"], cwd=workdir, check=True)
    os.system("exit 0")
    pid = os.posix_spawn(sys.executable, [sys.executable, "-c", "pass"], {})
    os.waitpid(pid, 0)
    with socket.create_connection(("127.0.0.1", port), timeout=2):
        pass


def main() -> None:
    global recording
    with tempfile.TemporaryDirectory() as tmp, socket.socket() as listener:
        workdir = Path(tmp)
        (workdir / "credentials").write_text("[default]\naws_secret_access_key = fixture\n")
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]

        subprocess.Popen = PopenSpy(subprocess.Popen)
        sys.addaudithook(observer)
        recording = True
        suspicious_plugin(workdir, port)
        recording = False
        subprocess.Popen = subprocess.Popen.real

    print(f"noncompliant: Popen wrapper saw {len(PopenSpy.calls)} of 3 process launches:")
    for call in PopenSpy.calls:
        print(f"noncompliant:   {call}")
    print(f"compliant:    audit hook saw {len(seen)} events:")
    for event in seen:
        print(f"compliant:      {event}")

    sys.addaudithook(no_outbound_network)  # from here on, for the rest of the process
    try:
        socket.create_connection(("192.0.2.10", 443), timeout=2)  # TEST-NET-1, never reached
    except PermissionError as exc:
        print(f"compliant:    tripwire: {exc}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: Popen wrapper saw 1 of 3 process launches:
# noncompliant:   Popen argv[1:]=['-c', 'pass']
# compliant:    audit hook saw 5 events:
# compliant:      open credentials mode=r
# compliant:      subprocess.Popen argv[1:]=['-c', 'pass']
# compliant:      os.system 'exit 0'
# compliant:      os.posix_spawn argv[1:]=['-c', 'pass']
# compliant:      socket.connect host=127.0.0.1
# compliant:    tripwire: blocked connect to 192.0.2.10
