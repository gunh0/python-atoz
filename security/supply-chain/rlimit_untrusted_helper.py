"""CWE-770: running untrusted helpers — cap CPU, file size and descriptors with rlimits

https://cwe.mitre.org/data/definitions/770.html

Build steps and services run code they did not write: a converter from a
dependency, a plugin, a setup.py. A bug or a malicious payload in that helper
can spin forever, fill the disk or exhaust descriptors, and without limits it
takes the parent's machine down with it.

POSIX rlimits are set in the child between fork and exec (preexec_fn), so
they apply only to the helper: RLIMIT_CPU ends it with SIGXCPU, RLIMIT_FSIZE
makes oversized writes fail with EFBIG (CPython ignores SIGXFSZ), and
RLIMIT_NOFILE turns a descriptor leak into EMFILE. CPU limits do not see a
helper that sleeps, so add a wall-clock timeout. Memory limits are left out on
purpose: Linux enforces RLIMIT_AS but macOS refuses to lower it, so use
cgroups or a container for memory. This is a seat belt, not a sandbox.
"""

import errno
import os
import re
import resource
import signal
import subprocess
import sys
import tempfile

HELPERS = {  # what a misbehaving helper might do
    "spin": "while True: pass",
    "fill disk": "open('out.bin', 'wb').write(b'x' * (8 << 20))",
    "leak fds": "import os\nfs = []\nwhile len(fs) < 200: fs.append(open(os.devnull))",
    "hang": "import time; time.sleep(60)",
}
LIMITS = {
    resource.RLIMIT_CPU: (1, 2),  # seconds of CPU: SIGXCPU at 1, SIGKILL at 2
    resource.RLIMIT_FSIZE: (1 << 20, 1 << 20),  # largest file the helper may write: 1 MiB
    resource.RLIMIT_NOFILE: (64, 64),
    resource.RLIMIT_CORE: (0, 0),  # no core dumps of a process that may hold secrets
}


def apply_limits() -> None:
    for which, value in LIMITS.items():
        resource.setrlimit(which, value)


def describe(proc: subprocess.CompletedProcess) -> str:
    if proc.returncode < 0:
        return f"killed by {signal.Signals(-proc.returncode).name}"
    if proc.returncode:
        m = re.search(r"^(\w+): \[Errno (\d+)\]", proc.stderr, re.MULTILINE)
        return f"{m[1]} {errno.errorcode[int(m[2])]}" if m else "failed"
    return "finished normally"


def run(code: str, cwd: str, limited: bool, timeout: float = 5.0) -> str:
    try:
        proc = subprocess.run([sys.executable, "-I", "-c", code], cwd=cwd, env={},
                              capture_output=True, text=True, timeout=timeout,
                              preexec_fn=apply_limits if limited else None)
    except subprocess.TimeoutExpired:
        return f"killed after {timeout} s wall-clock timeout"
    return describe(proc)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "out.bin")
        for name in ("fill disk", "leak fds"):
            result = run(HELPERS[name], tmp, limited=False)
            extra = f", wrote {os.path.getsize(out) >> 20} MiB" if name == "fill disk" else ""
            print(f"noncompliant: {name:9} -> {result}{extra}")
            if os.path.exists(out):
                os.remove(out)
        for name, code in HELPERS.items():
            result = run(code, tmp, limited=True, timeout=0.5 if name == "hang" else 5.0)
            extra = f", file <= 1 MiB: {os.path.getsize(out) <= 1 << 20}" if name == "fill disk" else ""
            print(f"compliant:    {name:9} -> {result}{extra}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: fill disk -> finished normally, wrote 8 MiB
# noncompliant: leak fds  -> finished normally
# compliant:    spin      -> killed by SIGXCPU
# compliant:    fill disk -> OSError EFBIG, file <= 1 MiB: True
# compliant:    leak fds  -> OSError EMFILE
# compliant:    hang      -> killed after 0.5 s wall-clock timeout
