"""Tar slip via links (CWE-59/CWE-22): what each extraction filter allows

https://cwe.mitre.org/data/definitions/59.html   (PEP 706)

Follow-up to tar_slip_extraction_filter. Rejecting "../" in member names is
not enough, because a tar archive can also contain links. A symlink member
"app/escape -> ../../../outside" followed by a regular member
"app/escape/pwned.txt" writes through the link, outside the destination; an
absolute symlink or hard link to a secret makes the secret appear inside the
extracted tree, where a web server or a later "re-pack" will happily serve it.

The three built-in filters differ exactly here:
  fully_trusted  everything, as stored (the pre-3.14 default)
  tar            strips "/" and refuses members whose resolved path leaves
                 dest (so pwned.txt is caught), but extracts any link
  data           also refuses absolute links and links that leave dest
Run with filter="data" for anything you did not build yourself, and stay on a
current patch release: the filters themselves received security fixes.
Output verified on 3.13.16, 3.14.8 and 3.15.0.
"""

import io
import tarfile
import tempfile
from pathlib import Path


def member(name: str, kind: bytes = tarfile.REGTYPE, data: bytes = b"", link: str = ""):
    info = tarfile.TarInfo(name)
    info.type, info.linkname, info.size = kind, link, len(data)
    info.mode, info.mtime = 0o644, 1_700_000_000
    return info, io.BytesIO(data) if kind == tarfile.REGTYPE else None


def make_archive(root: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for info, data in [
            member("app/README", data=b"hello"),
            member("app/readme-link", tarfile.SYMTYPE, link="README"),
            member("app/config", tarfile.SYMTYPE, link=f"{root}/secret.txt"),
            member("app/hard", tarfile.LNKTYPE, link=f"{root}/secret.txt"),
            member("app/escape", tarfile.SYMTYPE, link="../../../outside"),
            member("app/escape/pwned.txt", data=b"TAR-SLIP through symlink"),
        ]:
            tar.addfile(info, data)
    return buf.getvalue()


def extract(data: bytes, dest: Path, filter_name: str) -> list[str]:
    results = []
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for m in tar.getmembers():
            try:
                tar.extract(m, dest, filter=filter_name)
                results.append(f"{m.name:22} extracted")
            except (tarfile.FilterError, OSError) as exc:
                results.append(f"{m.name:22} refused: {type(exc).__name__}")
    return results


def main() -> None:
    for filter_name in ("fully_trusted", "tar", "data"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            dest = root / "work" / "dest"
            dest.mkdir(parents=True)
            (root / "outside").mkdir()
            (root / "secret.txt").write_text("db_password=hunter2")
            print(f"filter={filter_name!r}")
            for line in extract(make_archive(root), dest, filter_name):
                print(f"  {line}")
            config = dest / "app" / "config"
            hard = dest / "app" / "hard"
            print(f"  -> secret readable in dest:  "
                  f"{any(p.is_file() and 'hunter2' in p.read_text() for p in (config, hard))}")
            print(f"  -> file written outside:     {(root / 'outside' / 'pwned.txt').exists()}")


if __name__ == "__main__":
    main()

# Output:
# filter='fully_trusted'
#   app/README             extracted
#   app/readme-link        extracted
#   app/config             extracted
#   app/hard               extracted
#   app/escape             extracted
#   app/escape/pwned.txt   extracted
#   -> secret readable in dest:  True
#   -> file written outside:     True
# filter='tar'
#   app/README             extracted
#   app/readme-link        extracted
#   app/config             extracted
#   app/hard               extracted
#   app/escape             extracted
#   app/escape/pwned.txt   refused: OutsideDestinationError
#   -> secret readable in dest:  True
#   -> file written outside:     False
# filter='data'
#   app/README             extracted
#   app/readme-link        extracted
#   app/config             refused: AbsoluteLinkError
#   app/hard               refused: AbsoluteLinkError
#   app/escape             refused: LinkOutsideDestinationError
#   app/escape/pwned.txt   extracted
#   -> secret readable in dest:  False
#   -> file written outside:     False
