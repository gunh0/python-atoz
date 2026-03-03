"""CWE-732: loading secrets — env vars leak to children, files need permission checks

https://cwe.mitre.org/data/definitions/732.html    (CWE-526: https://cwe.mitre.org/data/definitions/526.html)

Environment variables are inherited by every subprocess, show up in
/proc/<pid>/environ and in crash reports, so a DB_PASSWORD read from the
environment and left there is handed to every tool the service shells out
to. Secret *files* (Docker and Kubernetes mount them; the convention is
DB_PASSWORD_FILE=/run/secrets/db_password) are better, but only if you refuse
files that others can read and do not follow a symlink an attacker planted.

The compliant loader prefers NAME_FILE, opens it with O_NOFOLLOW, and checks
the *opened* descriptor with fstat: a regular file, owned by us, no group or
other permission bits. A value that must come from the environment is popped
so children do not inherit it. Writing secrets uses O_EXCL and mode 0600
rather than open(path, "w"), which follows the umask.
"""

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


class SecretError(Exception):
    pass


def noncompliant_load(name: str) -> str:
    if f"{name}_FILE" in os.environ:
        return Path(os.environ[f"{name}_FILE"]).read_text().strip()
    return os.environ[name]  # stays in os.environ for every child process


def compliant_load(name: str, max_bytes: int = 4096) -> str:
    path = os.environ.get(f"{name}_FILE")
    if path is None:
        if name not in os.environ:
            raise SecretError(f"{name} not set")
        return os.environ.pop(name)  # take it out before anything is spawned
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise SecretError(f"{Path(path).name}: cannot open ({exc.strerror})") from None
    try:
        st = os.fstat(fd)  # check what we actually opened, not the path (no TOCTOU)
        if not stat.S_ISREG(st.st_mode):
            raise SecretError(f"{Path(path).name}: not a regular file")
        if st.st_uid != os.getuid():
            raise SecretError(f"{Path(path).name}: not owned by this user")
        if st.st_mode & 0o077:
            raise SecretError(f"{Path(path).name}: mode {stat.S_IMODE(st.st_mode):04o}, "
                              "group/other must have no access")
        with os.fdopen(os.dup(fd), "rb") as fh:
            data = fh.read(max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise SecretError(f"{Path(path).name}: larger than {max_bytes} bytes")
    return data.decode().rstrip("\r\n")


def write_secret(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(value + "\n")


def child_sees(name: str) -> bool:
    code = f"import os; print({name!r} in os.environ)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    return out.stdout.strip() == "True"


def main() -> None:
    os.umask(0o022)  # the common default, set explicitly so the output is stable
    os.environ["DB_PASSWORD"] = "S3cr3t!pw"
    noncompliant_load("DB_PASSWORD")
    print(f"noncompliant: env secret visible to child process: {child_sees('DB_PASSWORD')}")
    compliant_load("DB_PASSWORD")
    print(f"compliant:    env secret visible to child process: {child_sees('DB_PASSWORD')}")

    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "loose_password").write_text("S3cr3t!pw\n")  # open(..., "w"): 0666 & ~umask
        write_secret(d / "db_password", "S3cr3t!pw")
        (d / "planted_link").symlink_to(d / "db_password")
        (d / "a_directory").mkdir(mode=0o700)
        print(f"noncompliant: open(path, 'w') created mode {stat.S_IMODE((d / 'loose_password').stat().st_mode):04o}")
        print(f"compliant:    O_EXCL + 0600 created mode  {stat.S_IMODE((d / 'db_password').stat().st_mode):04o}")

        for candidate in ("db_password", "loose_password", "planted_link", "a_directory", "missing"):
            os.environ["DB_PASSWORD_FILE"] = str(d / candidate)
            try:
                loose = f"loaded {len(noncompliant_load('DB_PASSWORD'))} chars"
            except OSError as exc:
                loose = f"error ({type(exc).__name__})"
            try:
                strict = f"loaded {len(compliant_load('DB_PASSWORD'))} chars"
            except SecretError as exc:
                strict = f"refused: {exc}"
            print(f"{candidate:15} noncompliant: {loose:25} compliant: {strict}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: env secret visible to child process: True
# compliant:    env secret visible to child process: False
# noncompliant: open(path, 'w') created mode 0644
# compliant:    O_EXCL + 0600 created mode  0600
# db_password     noncompliant: loaded 9 chars            compliant: loaded 9 chars
# loose_password  noncompliant: loaded 9 chars            compliant: refused: loose_password: mode 0644, group/other must have no access
# planted_link    noncompliant: loaded 9 chars            compliant: refused: planted_link: cannot open (Too many levels of symbolic links)
# a_directory     noncompliant: error (IsADirectoryError) compliant: refused: a_directory: not a regular file
# missing         noncompliant: error (FileNotFoundError) compliant: refused: missing: cannot open (No such file or directory)
