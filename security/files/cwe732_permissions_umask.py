"""CWE-732: incorrect permissions — set the mode when the file is created

https://cwe.mitre.org/data/definitions/732.html

open(path, "w") and Path.write_text() create files with 0o666 & ~umask. With
the usual umask 022 an API token file is world-readable (0o644); under a
service manager or in a container with umask 0 it is world-*writable*. The
common repair, chmod(0o600) afterwards, leaves a window in which another
user can open the file, and an open descriptor keeps working after the chmod.
os.makedirs(mode=0o700) only applies the mode to the last directory.

Pass the mode to os.open() so the file is born private, or set
os.umask(0o077) at the start of a process that writes secrets. When reading
a secret, refuse group/other-accessible files the way ssh refuses a 0o644
private key.
"""

import os
import stat
import tempfile
from pathlib import Path

TOKEN = "ghp_exampletoken000000000000000000000"


def mode(path: Path) -> str:
    return stat.filemode(path.stat().st_mode)


def noncompliant_write_then_chmod(path: Path, observe) -> None:
    path.write_text(TOKEN)
    observe(path)                       # another user's open() lands here
    path.chmod(0o600)


def compliant_create_private(path: Path, observe) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    observe(path)
    with os.fdopen(fd, "w") as f:
        f.write(TOKEN)


def load_secret(path: Path) -> str:
    st = path.stat()
    if st.st_mode & 0o077:
        raise PermissionError(f"{path.name} is {stat.filemode(st.st_mode)}, want -rw-------")
    return path.read_text()[:8] + "..."


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for umask in (0o022, 0o000):
            os.umask(umask)
            for fn in (noncompliant_write_then_chmod, compliant_create_private):
                path = root / f"token-{umask:03o}-{fn.__name__}"
                seen = []
                fn(path, lambda p: seen.append(mode(p)))
                print(f"umask {umask:03o} {fn.__name__:30} during write {seen[0]}  final {mode(path)}")
        print()
        os.umask(0o022)
        os.makedirs(root / "a" / "b" / "c", mode=0o700)
        for d in ("a", "a/b", "a/b/c"):
            print(f"makedirs(mode=0o700) {d:6} {mode(root / d)}")
        print()
        os.umask(0o077)
        (root / "cfg").write_text("with umask 077")
        print(f"umask 077 then write_text  {mode(root / 'cfg')}")
        os.umask(0o022)
        print()
        loose = root / "loose.token"
        loose.write_text(TOKEN)
        for p in (loose, root / "token-022-compliant_create_private"):
            try:
                print(f"load_secret({p.name}) -> {load_secret(p)}")
            except PermissionError as exc:
                print(f"load_secret({p.name}) -> refused: {exc}")


if __name__ == "__main__":
    main()

# Output:
# umask 022 noncompliant_write_then_chmod  during write -rw-r--r--  final -rw-------
# umask 022 compliant_create_private       during write -rw-------  final -rw-------
# umask 000 noncompliant_write_then_chmod  during write -rw-rw-rw-  final -rw-------
# umask 000 compliant_create_private       during write -rw-------  final -rw-------
#
# makedirs(mode=0o700) a      drwxr-xr-x
# makedirs(mode=0o700) a/b    drwxr-xr-x
# makedirs(mode=0o700) a/b/c  drwx------
#
# umask 077 then write_text  -rw-------
#
# load_secret(loose.token) -> refused: loose.token is -rw-r--r--, want -rw-------
# load_secret(token-022-compliant_create_private) -> ghp_exam...
