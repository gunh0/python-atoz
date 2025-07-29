"""CWE-59: link following — open() happily writes through an attacker's symlink

https://cwe.mitre.org/data/definitions/59.html

Any directory another user can write to (a shared spool, an upload area, a
user's home that a root cron job tidies up) lets that user replace the file
you are about to open with a symlink. open(path, "w") follows it and
truncates whatever the link points at, with *your* privileges. Reads leak the
same way.

os.open(..., O_NOFOLLOW) refuses a symlink in the last path component with
ELOOP. It does not look at the directories on the way, so a symlinked
directory still redirects the open; walk the path one component at a time
with dir_fd= and O_NOFOLLOW (plus O_DIRECTORY for the directories) when the
whole path is untrusted. Checking is_symlink() first is not a fix: it is a
race (see cwe367).
"""

import errno
import os
import tempfile
from pathlib import Path


def build(root: Path) -> Path:
    spool = root / "spool"            # writable by the attacker
    spool.mkdir()
    (root / "etc").mkdir()
    (root / "etc" / "app.conf").write_text("admin_password=hunter2\n")
    # Attacker plants links where the service will look.
    (spool / "report.txt").symlink_to(root / "etc" / "app.conf")
    (spool / "inbox").symlink_to(root / "etc", target_is_directory=True)
    return spool


def noncompliant_write(path: Path) -> str:
    with open(path, "w") as f:
        f.write("report generated\n")
    return "written"


def compliant_write(path: Path) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("report generated\n")
    return "written"


def nofollow_last_only(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        return f"read {f.read().strip()!r}"


def compliant_read_walk(base: Path, relpath: str) -> str:
    """Open base/relpath without following a symlink in *any* component."""
    parts = Path(relpath).parts
    if any(p in ("..", "/") for p in parts):
        raise PermissionError("bad component")
    dir_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    with os.fdopen(fd) as f:
        return f"read {f.read().strip()!r}"


# O_NOFOLLOW on a symlink fails with ELOOP on Linux and macOS (EMLINK on FreeBSD);
# adding O_DIRECTORY makes macOS report ENOTDIR instead. All mean "was a symlink".
SYMLINK_ERRNOS = {errno.ELOOP, errno.EMLINK, errno.ENOTDIR}


def attempt(fn, *args) -> str:
    try:
        return fn(*args)
    except OSError as exc:
        return "refused (symlink)" if exc.errno in SYMLINK_ERRNOS else f"refused ({exc!r})"


def main() -> None:
    for fn in (noncompliant_write, compliant_write):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spool = build(root)
            result = attempt(fn, spool / "report.txt")
            conf = (root / "etc" / "app.conf").read_text().strip()
            print(f"{fn.__name__:20} spool/report.txt -> {result:18} etc/app.conf now {conf!r}")
    print()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        spool = build(root)
        (spool / "notes.txt").write_text("hello\n")
        for rel in ("notes.txt", "report.txt", "inbox/app.conf"):
            print(f"read spool/{rel}")
            print(f"  O_NOFOLLOW on full path   {attempt(nofollow_last_only, spool / rel)}")
            print(f"  compliant dir_fd walk     {attempt(compliant_read_walk, spool, rel)}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant_write   spool/report.txt -> written            etc/app.conf now 'report generated'
# compliant_write      spool/report.txt -> refused (symlink)  etc/app.conf now 'admin_password=hunter2'
#
# read spool/notes.txt
#   O_NOFOLLOW on full path   read 'hello'
#   compliant dir_fd walk     read 'hello'
# read spool/report.txt
#   O_NOFOLLOW on full path   refused (symlink)
#   compliant dir_fd walk     refused (symlink)
# read spool/inbox/app.conf
#   O_NOFOLLOW on full path   read 'admin_password=hunter2'
#   compliant dir_fd walk     refused (symlink)
