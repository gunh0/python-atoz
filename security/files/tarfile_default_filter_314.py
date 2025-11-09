# requires-python: >=3.14
"""Python 3.14: tarfile extracts with filter="data" by default

https://cwe.mitre.org/data/definitions/22.html   (PEP 706; docs: tarfile extraction filters)

Up to 3.13, tarfile.extractall(dest) without a filter trusted the archive
completely (and warned with DeprecationWarning). From 3.14 the default is
the "data" filter from tar_slip_extraction_filter: traversal, absolute and
outside-pointing links, device files and setuid bits are refused or cleared
without anyone changing their code. shutil.unpack_archive() follows the same
default because it calls tarfile underneath.

Two consequences for reviewers. Old code got safer, but archives that
legitimately carry absolute symlinks (system backups, container layers) now
fail with AbsoluteLinkError, and the tempting "fix" is filter="fully_trusted"
or a global TarFile.extraction_filter override. Treat either as a security
decision that needs a reason in the code. And code that must also run on
3.13 should keep passing filter="data" explicitly; the default only helps
on 3.14+. Output verified on 3.14.8 and 3.15.0; the same file on 3.13.16
reports "extracted (+DeprecationWarning)" for every row.
"""

import io
import shutil
import tarfile
import tempfile
import warnings
from pathlib import Path


def archive(*members: tarfile.TarInfo) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for m in members:
            m.mtime = 1_700_000_000
            tar.addfile(m, io.BytesIO(b"x" * m.size) if m.isreg() else None)
    return buf.getvalue()


def reg(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = 1
    return info


def symlink(name: str, target: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = tarfile.SYMTYPE, target
    return info


def extract_default(data: bytes, dest: Path) -> str:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                tar.extractall(dest)                       # no filter argument
            result = "extracted"
        except tarfile.FilterError as exc:
            result = f"{type(exc).__name__}"
    dep = any(issubclass(w.category, DeprecationWarning) for w in caught)
    return f"{result}{' (+DeprecationWarning)' if dep else ''}"


def unpack_default(data: bytes, dest: Path) -> str:
    src = dest.parent / "upload.tar"
    src.write_bytes(data)
    try:
        shutil.unpack_archive(src, dest)
        return "extracted"
    except tarfile.FilterError as exc:
        return f"{type(exc).__name__}"


def main() -> None:
    print("TarFile.extraction_filter:", tarfile.TarFile.extraction_filter)
    cases = {
        "plain files": archive(reg("app/README")),
        "../ traversal": archive(reg("../escape.txt")),
        "absolute symlink": archive(symlink("lib/libc.so", "/usr/lib/libc.so.6")),
        "symlink leaving dest": archive(symlink("up", "../../..")),
    }
    for label, data in cases.items():
        results = []
        for fn in (extract_default, unpack_default):
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / "dest"
                dest.mkdir()
                results.append(fn(data, dest))
        print(f"{label:22} extractall(): {results[0]:28} shutil.unpack_archive(): {results[1]}")
    print()
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(fileobj=io.BytesIO(cases["absolute symlink"])) as tar:
            # A deliberate, documented opt-out for a trusted system backup:
            tar.extractall(tmp, filter="fully_trusted")
        print("explicit fully_trusted:", (Path(tmp) / "lib" / "libc.so").is_symlink())


if __name__ == "__main__":
    main()

# Output:
# TarFile.extraction_filter: None
# plain files            extractall(): extracted                    shutil.unpack_archive(): extracted
# ../ traversal          extractall(): OutsideDestinationError      shutil.unpack_archive(): OutsideDestinationError
# absolute symlink       extractall(): AbsoluteLinkError            shutil.unpack_archive(): AbsoluteLinkError
# symlink leaving dest   extractall(): LinkOutsideDestinationError  shutil.unpack_archive(): LinkOutsideDestinationError
#
# explicit fully_trusted: True
