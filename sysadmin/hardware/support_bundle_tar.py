"""Support bundle: collect hardware logs into a .tar.gz safely with tarfile

Vendors ask for a "support bundle" (RAID logs, SEL, sensor dumps, configs)
and the quick `tar czf bundle.tgz /etc /var/log` ships private keys,
passwords in config files and multi-GB core dumps to a third party. Build
the archive file by file instead and decide for each one:

- skip private keys and anything over a size limit;
- never follow symlinks (a link to /etc/shadow would pull in its content);
- redact `password=`/`secret=` values in configs, adding the edited bytes
  with TarInfo + addfile, so the original stays untouched;
- normalise owner, mode and mtime and write gzip with mtime=0, so the same
  input gives the same bytes (easy to diff, no leaked usernames).

On the receiving side, extract only with filter="data" (the default from
Python 3.14), which rejects members escaping the target directory and links
to absolute paths, and quietly strips the leading "/" from absolute names.
"""

import gzip
import io
import os
import re
import stat
import tarfile
import tempfile
from pathlib import Path

MAX_BYTES = 1024 * 1024
SKIP_SUFFIXES = (".key", ".pem")
REDACT = re.compile(r"(?im)^(\s*\w*(?:password|secret|token)\w*\s*=\s*).+$")

SAMPLE_FILES = {
    "raid/megacli-pdlist.txt": "Enclosure Device ID: 32\nSlot Number: 3\nMedia Error Count: 14\n",
    "raid/megacli-events.txt": "seqNum: 0x00004a1f\nEvent Description: Predictive failure: PD 03(e0x20/s3)\n",
    "ipmi/sel-list.txt": "   1 | 09/14/2026 | 02:11:40 | Fan FAN3 | Lower Critical going low | Asserted\n",
    "ipmi/sensor.txt": "FAN3             | 420.000    | RPM        | cr    | 300.000   | 500.000\n",
    "conf/agent.ini": "[bmc]\nhost = 10.10.0.21\nuser = admin\npassword = Bmc!2026pw\n",
    "conf/ssl/agent.key": "-----BEGIN PRIVATE KEY-----\n(not really a key)\n-----END PRIVATE KEY-----\n",
}


def make_sample_tree(root: Path) -> None:
    for rel, text in SAMPLE_FILES.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "crash").mkdir()
    (root / "crash/core.4711").write_bytes(b"\0" * (2 * MAX_BYTES))
    (root / "conf/shadow-link").symlink_to("/etc/shadow")


def normalised(info: tarfile.TarInfo, size: int) -> tarfile.TarInfo:
    info.size = size
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mode = 0o644
    info.mtime = 1_789_344_000  # fixed timestamp for reproducible archives
    return info


def build_bundle(source: Path, out: Path, prefix: str) -> list[str]:
    notes = []
    with open(out, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(source.rglob("*")):
            rel = path.relative_to(source).as_posix()
            if path.is_symlink():
                notes.append(f"skip {rel}: symlink -> {os.readlink(path)}")
                continue
            if not path.is_file():
                continue
            if path.suffix in SKIP_SUFFIXES:
                notes.append(f"skip {rel}: private key material")
                continue
            if path.stat().st_size > MAX_BYTES:
                notes.append(f"skip {rel}: {path.stat().st_size // 1024} KiB > limit")
                continue
            data = path.read_bytes()
            if path.suffix in (".ini", ".conf"):
                text, count = REDACT.subn(r"\1<redacted>", data.decode("utf-8"))
                if count:
                    notes.append(f"redact {rel}: {count} value(s)")
                data = text.encode("utf-8")
            info = normalised(tarfile.TarInfo(f"{prefix}/{rel}"), len(data))
            tar.addfile(info, io.BytesIO(data))
    return notes


def hostile_members() -> list[tarfile.TarInfo]:
    members = []
    for name in ("logs/ok.txt", "../../etc/cron.d/backdoor", "/etc/profile.d/evil.sh"):
        members.append(tarfile.TarInfo(name))
    link = tarfile.TarInfo("logs/passwd")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    members.append(link)
    return members


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, out = Path(tmp, "collect"), Path(tmp, "bundle.tar.gz")
        make_sample_tree(source)
        for note in build_bundle(source, out, "support-db01"):
            print(note)

        print()
        with tarfile.open(out, "r:gz") as tar:
            for m in tar.getmembers():
                print(f"{stat.filemode(m.mode | stat.S_IFREG)} {m.uname}/{m.gname} {m.size:>5} {m.name}")
            agent = tar.extractfile("support-db01/conf/agent.ini")
            assert agent is not None
            print("agent.ini password line:", agent.read().decode().splitlines()[-1])

        first = out.read_bytes()
        build_bundle(source, out, "support-db01")
        print("rebuilt archive byte-identical:", first == out.read_bytes())

        print()
        dest = Path(tmp, "extract")
        for member in hostile_members():
            try:
                result = tarfile.data_filter(member, str(dest))
                print(f"data filter: {member.name:<28} ok -> {result.name}")
            except tarfile.FilterError as exc:
                print(f"data filter: {member.name:<28} rejected ({type(exc).__name__})")


if __name__ == "__main__":
    main()

# Output:
# redact conf/agent.ini: 1 value(s)
# skip conf/shadow-link: symlink -> /etc/shadow
# skip conf/ssl/agent.key: private key material
# skip crash/core.4711: 2048 KiB > limit
#
# -rw-r--r-- root/root    59 support-db01/conf/agent.ini
# -rw-r--r-- root/root    78 support-db01/ipmi/sel-list.txt
# -rw-r--r-- root/root    73 support-db01/ipmi/sensor.txt
# -rw-r--r-- root/root    74 support-db01/raid/megacli-events.txt
# -rw-r--r-- root/root    61 support-db01/raid/megacli-pdlist.txt
# agent.ini password line: password = <redacted>
# rebuilt archive byte-identical: True
#
# data filter: logs/ok.txt                  ok -> logs/ok.txt
# data filter: ../../etc/cron.d/backdoor    rejected (OutsideDestinationError)
# data filter: /etc/profile.d/evil.sh       ok -> etc/profile.d/evil.sh
# data filter: logs/passwd                  rejected (AbsoluteLinkError)
