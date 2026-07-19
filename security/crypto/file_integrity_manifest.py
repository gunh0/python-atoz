"""CWE-354: file integrity manifests — sha256sum-style create and verify, done fully

https://cwe.mitre.org/data/definitions/354.html

A SHA256SUMS file next to a release looks like integrity, and `sha256sum -c`
prints OK for every line. But it only checks the files the manifest lists:
a dropped-in sitecustomize.py is never mentioned. And if the manifest is not
authenticated, whoever can change a file can change its line too, and every
check still says OK.

The compliant verifier authenticates the manifest first (an HMAC here; a
detached signature such as minisign, GPG or Sigstore for public releases),
rejects entries with absolute or ".." paths, streams each file through
hashlib.file_digest, and reports listed files that changed or vanished *and*
files on disk that the manifest does not list.
"""

import hashlib
import hmac
import tempfile
from pathlib import Path, PurePosixPath

RELEASE_KEY = bytes.fromhex("9a" * 32)  # held by the release pipeline, not the web server
FILES = {
    "bin/tool": b"#!/bin/sh\nexec python3 -m tool \"$@\"\n",
    "lib/tool/__init__.py": b"VERSION = '1.4.2'\n",
    "lib/tool/util.py": b"def run():\n    return 'ok'\n",
    "README": b"tool 1.4.2\n",
}


def sha256_file(path: Path) -> str:
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def create_manifest(root: Path) -> tuple[str, str]:
    lines = [f"{sha256_file(p)}  {p.relative_to(root).as_posix()}"
             for p in sorted(root.rglob("*")) if p.is_file()]
    text = "\n".join(lines) + "\n"
    return text, hmac.new(RELEASE_KEY, text.encode(), hashlib.sha256).hexdigest()


def parse(text: str) -> dict[str, str]:
    entries = {}
    for line in text.splitlines():
        digest, _, name = line.partition("  ")
        rel = PurePosixPath(name.removeprefix("*"))  # "*" marks binary mode in sha256sum
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(f"unsafe path in manifest: {name}")
        entries[str(rel)] = digest
    return entries


def noncompliant_verify(root: Path, text: str) -> list[str]:
    report = []
    for name, digest in parse(text).items():
        path = root / name
        status = "OK" if path.is_file() and sha256_file(path) == digest else "FAILED"
        report.append(f"{name}: {status}")
    return report


def compliant_verify(root: Path, text: str, mac: str) -> list[str]:
    expected = hmac.new(RELEASE_KEY, text.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        return ["manifest authentication FAILED, nothing trusted"]
    try:
        entries = parse(text)
    except ValueError as exc:
        return [str(exc)]
    report = []
    for name, digest in entries.items():
        path = root / name
        if not path.is_file():
            report.append(f"{name}: MISSING")
        elif not hmac.compare_digest(sha256_file(path), digest):
            report.append(f"{name}: FAILED")
    on_disk = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    report += [f"{name}: NOT IN MANIFEST" for name in sorted(on_disk - entries.keys())]
    return report or ["all files verified, nothing extra"]


def build(root: Path) -> None:
    for name, data in FILES.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        build(root)
        manifest, mac = create_manifest(root)
        print("SHA256SUMS:")
        for line in manifest.splitlines():
            print(f"  {line[:16]}...  {line.split('  ', 1)[1]}")
        print(f"pristine:  compliant: {compliant_verify(root, manifest, mac)}")

        # 1. Attacker with write access to the files *and* the unauthenticated manifest.
        (root / "lib/tool/util.py").write_bytes(b"import os\ndef run():\n    os.system('id')\n")
        (root / "lib/tool/sitecustomize.py").write_bytes(b"print('loaded on every start')\n")
        new_digest = sha256_file(root / "lib/tool/util.py")
        forged = "".join(f"{new_digest}  lib/tool/util.py\n" if line.endswith("  lib/tool/util.py") else
                         f"{line}\n" for line in manifest.splitlines())
        print(f"rewritten: noncompliant: {noncompliant_verify(root, forged)}")
        print(f"rewritten: compliant:    {compliant_verify(root, forged, mac)}")

        # 2. Same tampering, manifest left alone, and README deleted.
        (root / "README").unlink()
        print(f"tampered:  noncompliant: {noncompliant_verify(root, manifest)}")
        print(f"tampered:  compliant:    {compliant_verify(root, manifest, mac)}")

        evil = "0" * 64 + "  ../../home/user/.ssh/authorized_keys\n"
        evil_mac = hmac.new(RELEASE_KEY, evil.encode(), hashlib.sha256).hexdigest()
        print(f"traversal: compliant:    {compliant_verify(root, evil, evil_mac)}")


if __name__ == "__main__":
    main()

# Output:
# SHA256SUMS:
#   911a5ef5500ea475...  README
#   81ed681588b203b2...  bin/tool
#   dfe19c3ee29c02a5...  lib/tool/__init__.py
#   ea5612643e5addd5...  lib/tool/util.py
# pristine:  compliant: ['all files verified, nothing extra']
# rewritten: noncompliant: ['README: OK', 'bin/tool: OK', 'lib/tool/__init__.py: OK', 'lib/tool/util.py: OK']
# rewritten: compliant:    ['manifest authentication FAILED, nothing trusted']
# tampered:  noncompliant: ['README: FAILED', 'bin/tool: OK', 'lib/tool/__init__.py: OK', 'lib/tool/util.py: FAILED']
# tampered:  compliant:    ['README: MISSING', 'lib/tool/util.py: FAILED', 'lib/tool/sitecustomize.py: NOT IN MANIFEST']
# traversal: compliant:    ['unsafe path in manifest: ../../home/user/.ssh/authorized_keys']
