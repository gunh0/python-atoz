"""CWE-22: path traversal — resolve the path, then check it is inside the base

https://cwe.mitre.org/data/definitions/22.html

A download handler that does open(os.path.join(UPLOADS, name)) serves any
file the process can read: "../" climbs out, and an absolute name makes
os.path.join() throw the base away entirely. The usual patches are each
broken in their own way: stripping "../" once turns "....//" into "../", and
a str.startswith(base) check accepts the sibling directory "uploads-private"
because it shares the prefix "uploads".

Resolve the joined path (which also collapses ".." and follows symlinks),
resolve the base too, and compare whole path components with
Path.is_relative_to(). Reject the request otherwise. Paths printed below are
relative to the demo's temporary directory.
"""

import os
import tempfile
from pathlib import Path

NAMES = [
    "report.txt",
    "sub/../report.txt",
    "../config.ini",
    "....//config.ini",
    "../uploads-private/salary.csv",
    "{root}/srv/config.ini",         # absolute path, filled in at runtime
]


def build(root: Path) -> Path:
    srv = root / "srv"
    (srv / "uploads" / "sub").mkdir(parents=True)
    (srv / "uploads-private").mkdir()
    (srv / "uploads" / "report.txt").write_text("quarterly report")
    (srv / "config.ini").write_text("db_password=hunter2")
    (srv / "uploads-private" / "salary.csv").write_text("ada,250000")
    return srv / "uploads"


def noncompliant_join(base: Path, name: str) -> str:
    return open(os.path.join(base, name)).read()


def noncompliant_strip(base: Path, name: str) -> str:
    return open(os.path.join(base, name.replace("../", ""))).read()


def noncompliant_prefix(base: Path, name: str) -> str:
    path = os.path.abspath(os.path.join(base, name))
    if not path.startswith(str(base)):
        raise PermissionError("outside base")
    return open(path).read()


def compliant(base: Path, name: str) -> str:
    base = base.resolve()
    path = (base / name).resolve()
    if not path.is_relative_to(base):
        raise PermissionError("outside base")
    return path.read_text()


def attempt(fn, base: Path, name: str) -> str:
    try:
        return f"read {fn(base, name)!r}"
    except (PermissionError, FileNotFoundError) as exc:
        return f"{type(exc).__name__}"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        base = build(root)
        for template in NAMES:
            name = template.format(root=root)
            print(f"name {template.replace('{root}', '<tmp>')!r}")
            for fn in (noncompliant_join, noncompliant_strip, noncompliant_prefix, compliant):
                print(f"  {fn.__name__:20} {attempt(fn, base, name)}")


if __name__ == "__main__":
    main()

# Output:
# name 'report.txt'
#   noncompliant_join    read 'quarterly report'
#   noncompliant_strip   read 'quarterly report'
#   noncompliant_prefix  read 'quarterly report'
#   compliant            read 'quarterly report'
# name 'sub/../report.txt'
#   noncompliant_join    read 'quarterly report'
#   noncompliant_strip   FileNotFoundError
#   noncompliant_prefix  read 'quarterly report'
#   compliant            read 'quarterly report'
# name '../config.ini'
#   noncompliant_join    read 'db_password=hunter2'
#   noncompliant_strip   FileNotFoundError
#   noncompliant_prefix  PermissionError
#   compliant            PermissionError
# name '....//config.ini'
#   noncompliant_join    FileNotFoundError
#   noncompliant_strip   read 'db_password=hunter2'
#   noncompliant_prefix  FileNotFoundError
#   compliant            FileNotFoundError
# name '../uploads-private/salary.csv'
#   noncompliant_join    read 'ada,250000'
#   noncompliant_strip   FileNotFoundError
#   noncompliant_prefix  read 'ada,250000'
#   compliant            PermissionError
# name '<tmp>/srv/config.ini'
#   noncompliant_join    read 'db_password=hunter2'
#   noncompliant_strip   read 'db_password=hunter2'
#   noncompliant_prefix  PermissionError
#   compliant            PermissionError
