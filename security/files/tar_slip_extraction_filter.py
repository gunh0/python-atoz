"""Tar slip (CWE-22): pass filter="data" to every tarfile extraction

https://cwe.mitre.org/data/definitions/22.html   (PEP 706, CVE-2007-4559)

Unlike zipfile, tarfile.extractall() historically trusted the archive
completely: "../" and absolute member names land outside the destination,
mode bits including setuid are restored as stored, and links (next unit) can
point anywhere. Up to Python 3.13 that is still what happens when no filter
is given (plus a DeprecationWarning); the explicit spelling is
filter="fully_trusted".

Since 3.12 (and in security backports) extraction takes a filter. "data" is
the one for archives from anyone else: it refuses members that would land
outside the destination, strips leading "/", clears setuid/setgid/sticky and
group/other write bits, and rejects device files and dangerous links. Pass
it explicitly so the code behaves the same on every version; 3.14 made it the
default (see tarfile_default_filter_314).
"""

import io
import stat
import tarfile
import tempfile
from pathlib import Path


def add(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), mode, 1_700_000_000
    tar.addfile(info, io.BytesIO(data))


def make_archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        add(tar, "app/README", b"hello")
        add(tar, "app/bin/helper", b"#!/bin/sh\n", mode=0o4777)   # setuid, world-writable
        add(tar, "../outside.txt", b"TAR-SLIP relative")
        add(tar, "app/../../victim.txt", b"TAR-SLIP nested")
    return buf.getvalue()


def listing(root: Path) -> list[str]:
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(root))
            where = "" if rel.startswith("work/dest/") else "   <-- outside dest"
            out.append(f"{stat.filemode(p.stat().st_mode)} {rel}{where}")
    return out


def noncompliant(data: bytes, dest: Path) -> str:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(dest, filter="fully_trusted")   # == the 3.13 default
    return "extracted everything"


def compliant(data: bytes, dest: Path) -> str:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        try:
            tar.extractall(dest, filter="data")
        except tarfile.FilterError as exc:
            return f"stopped: {type(exc).__name__} for {exc.tarinfo.name!r}"
    return "extracted everything"


def compliant_skip(data: bytes, dest: Path) -> str:
    """Same filter, applied per member: keep the good ones, report the rest."""
    skipped = []
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar.getmembers():
            try:
                tar.extract(member, dest, filter="data")
            except tarfile.FilterError as exc:
                skipped.append(f"{member.name} ({type(exc).__name__})")
    return "skipped " + ", ".join(skipped)


def main() -> None:
    for fn in (noncompliant, compliant, compliant_skip):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / "work" / "dest"
            dest.mkdir(parents=True)
            print(f"{fn.__name__}: {fn(make_archive(), dest)}")
            for line in listing(root):
                print(f"  {line}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: extracted everything
#   -rw-r--r-- work/dest/app/README
#   -rwsrwxrwx work/dest/app/bin/helper
#   -rw-r--r-- work/outside.txt   <-- outside dest
#   -rw-r--r-- work/victim.txt   <-- outside dest
# compliant: stopped: OutsideDestinationError for '../outside.txt'
#   -rw-r--r-- work/dest/app/README
#   -rwxr-xr-x work/dest/app/bin/helper
# compliant_skip: skipped ../outside.txt (OutsideDestinationError), app/../../victim.txt (OutsideDestinationError)
#   -rw-r--r-- work/dest/app/README
#   -rwxr-xr-x work/dest/app/bin/helper
