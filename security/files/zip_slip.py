"""Zip slip (CWE-22): archive member names are untrusted paths

https://cwe.mitre.org/data/definitions/22.html

A member name in a zip file is just a string chosen by whoever built the
archive. Code that extracts by hand, os.path.join(dest, info.filename), writes
"../../home/app/.bashrc" outside the destination, and an absolute member name
replaces dest altogether. This is the classic zip slip of plugin uploaders and
"import backup" features.

ZipFile.extract()/extractall() sanitise names: they drop "..", leading
slashes and drive letters. If you extract yourself (to stream, filter by
type, or rename), apply the same rule as for any path from a user: resolve
under the destination and require is_relative_to(dest). Also cap the total
uncompressed size while reading; the sizes in the zip header are attacker
data too.
"""

import io
import os
import tempfile
import zipfile
from pathlib import Path

MAX_TOTAL = 1 << 20


def make_archive(root: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("plugin/manifest.json", '{"name": "demo"}')
        zf.writestr("../outside.txt", "ZIP-SLIP relative")
        zf.writestr("plugin/../../victim/cron.txt", "ZIP-SLIP nested")
        zf.writestr(f"{root}/victim/absolute.txt", "ZIP-SLIP absolute")
    return buf.getvalue()


def noncompliant(data: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            target = os.path.join(dest, info.filename)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(zf.read(info))


def library(data: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(dest)


def compliant(data: bytes, dest: Path) -> list[str]:
    dest = dest.resolve()
    skipped, total = [], 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest) or info.is_dir():
                skipped.append(info.filename)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "xb") as out:
                while chunk := src.read(65536):
                    total += len(chunk)
                    if total > MAX_TOTAL:
                        raise ValueError("archive expands beyond limit")
                    out.write(chunk)
    return skipped


def tree(root: Path) -> list[str]:
    names = (str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    # extractall() keeps an absolute name as a relative one: show it without the temp path.
    return sorted(n.replace(str(root).lstrip("/"), "<tmp>") for n in names)


def main() -> None:
    for fn in (noncompliant, library, compliant):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            dest = root / "work" / "extract"
            dest.mkdir(parents=True)
            (root / "victim").mkdir()
            skipped = fn(make_archive(root), dest)
            print(f"{fn.__name__}:")
            for name in tree(root):
                outside = "" if name.startswith("work/extract/") else "   <-- outside dest"
                print(f"  {name}{outside}")
            for name in skipped or []:
                print(f"  skipped {name.replace(str(root), '<tmp>')!r}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant:
#   victim/absolute.txt   <-- outside dest
#   work/extract/plugin/manifest.json
#   work/outside.txt   <-- outside dest
#   work/victim/cron.txt   <-- outside dest
# library:
#   work/extract/<tmp>/victim/absolute.txt
#   work/extract/outside.txt
#   work/extract/plugin/manifest.json
#   work/extract/plugin/victim/cron.txt
# compliant:
#   work/extract/plugin/manifest.json
#   skipped '../outside.txt'
#   skipped 'plugin/../../victim/cron.txt'
#   skipped '<tmp>/victim/absolute.txt'
