"""CWE-367: TOCTOU — check the file you opened, not the name you checked

https://cwe.mitre.org/data/definitions/367.html

"if not os.path.exists(p): open(p, 'w')" and "if not os.path.islink(p):
open(p)" each ask the file system a question about a *name*, then act on the
name again later. In between, another process can create or swap that name;
the check passes, the open follows the attacker's symlink. Retrying faster or
adding more checks does not close the window.

Let the kernel do check and use in one step: os.open with O_CREAT | O_EXCL
(create, fail if anything exists) and O_NOFOLLOW (fail on a symlink), then
make every further decision with os.fstat() on the descriptor you hold, which
cannot be swapped. The window is made deterministic below with a `between`
hook that plays the attacker exactly once.
"""

import os
import stat
import tempfile
from pathlib import Path


def noncompliant_create(path: Path, between) -> str:
    if os.path.exists(path):
        return "refused: exists"
    between()
    with open(path, "w") as f:
        f.write("job=42\n")
    return "written"


def compliant_create(path: Path, between) -> str:
    between()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return "refused: exists (atomic)"
    with os.fdopen(fd, "w") as f:
        f.write("job=42\n")
    return "written"


def noncompliant_read(path: Path, between) -> str:
    if os.path.islink(path) or not os.path.isfile(path):
        return "refused: not a regular file"
    between()
    return "read " + repr(path.read_text().strip())


def compliant_read(path: Path, between, owner: int) -> str:
    between()
    try:
        # O_NONBLOCK: opening a FIFO returns at once instead of waiting for a writer
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return "refused: symlink or missing"
    with os.fdopen(fd) as f:
        st = os.fstat(f.fileno())               # facts about *this* open file
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner:
            return "refused: fstat check"
        return "read " + repr(f.read().strip())


def scenario(fn, *extra, swap: str = "symlink") -> str:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        secret = root / "shadow"
        secret.write_text("root:$6$hash")
        target = root / "spool" / "job.txt"
        target.parent.mkdir()
        if fn.__name__.endswith("read"):
            target.write_text("job=41")         # a legitimate file passes the check...

        def between() -> None:                  # ...then the attacker swaps the name
            target.unlink(missing_ok=True)
            if swap == "symlink":
                target.symlink_to(secret)
            else:
                os.mkfifo(target)               # open() for reading would hang forever

        result = fn(target, between, *extra)
        return f"{result:30} shadow now {secret.read_text()!r}"


def main() -> None:
    print("create spool/job.txt")
    print("  noncompliant exists()+open ", scenario(noncompliant_create))
    print("  compliant O_EXCL|O_NOFOLLOW", scenario(compliant_create))
    print("read spool/job.txt")
    print("  noncompliant islink()+open ", scenario(noncompliant_read))
    print("  compliant O_NOFOLLOW+fstat ", scenario(compliant_read, os.getuid()))
    print("read spool/job.txt, swapped for a FIFO")
    print("  noncompliant islink()+open  (not run: blocks forever in open())")
    print("  compliant O_NOFOLLOW+fstat ", scenario(compliant_read, os.getuid(), swap="fifo"))


if __name__ == "__main__":
    main()

# Output:
# create spool/job.txt
#   noncompliant exists()+open  written                        shadow now 'job=42\n'
#   compliant O_EXCL|O_NOFOLLOW refused: exists (atomic)       shadow now 'root:$6$hash'
# read spool/job.txt
#   noncompliant islink()+open  read 'root:$6$hash'            shadow now 'root:$6$hash'
#   compliant O_NOFOLLOW+fstat  refused: symlink or missing    shadow now 'root:$6$hash'
# read spool/job.txt, swapped for a FIFO
#   noncompliant islink()+open  (not run: blocks forever in open())
#   compliant O_NOFOLLOW+fstat  refused: fstat check           shadow now 'root:$6$hash'
