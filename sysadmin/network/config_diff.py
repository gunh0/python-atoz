"""Running-config backup with change detection and a unified diff

The minimum useful config backup: fetch `show running-config`, store it
only if it differs from the last stored copy (compare a SHA-256 of the
content), and when it differs, print a unified diff so a human can see what
changed between two nightly runs. difflib.unified_diff produces the same
format as `diff -u`, so the output pastes cleanly into a ticket or a commit.

Files are written atomically (write to a temporary name, then os.replace),
so a crash mid-write never leaves a truncated "latest" config behind -- the
one you will need on the day the switch dies.

Note the first and second fetch below: nothing was configured in between,
yet IOS changed its header lines, so a new copy is stored. Fine for now.
"""

import difflib
import hashlib
import os
import tempfile
from pathlib import Path

FETCHES = [
    ("2026-09-14 02:00", """\
Building configuration...

Current configuration : 1873 bytes
!
! Last configuration change at 17:41:08 KST Fri Sep 11 2026 by netops
!
version 16.9
hostname edge-sw02
!
interface GigabitEthernet1/0/5
 description mon01
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/6
 switchport access vlan 10
 switchport mode access
!
ntp server 10.0.0.123
end
"""),
    ("2026-09-15 02:00", """\
Building configuration...

Current configuration : 1873 bytes
!
! Last configuration change at 17:41:08 KST Fri Sep 11 2026 by netops
! NVRAM config last updated at 23:10:44 KST Mon Sep 14 2026 by netops
!
version 16.9
hostname edge-sw02
!
interface GigabitEthernet1/0/5
 description mon01
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/6
 switchport access vlan 10
 switchport mode access
!
ntp server 10.0.0.123
end
"""),
    ("2026-09-16 02:00", """\
Building configuration...

Current configuration : 1952 bytes
!
! Last configuration change at 15:02:51 KST Tue Sep 15 2026 by kim
! NVRAM config last updated at 23:10:44 KST Mon Sep 14 2026 by netops
!
version 16.9
hostname edge-sw02
!
interface GigabitEthernet1/0/5
 description mon01
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/6
 description bk-nas02
 switchport access vlan 20
 switchport mode access
!
ntp server 10.0.0.123
ntp server 10.0.0.124
end
"""),
    ("2026-09-17 02:00", None),  # same as previous: fetch returns identical text
]


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def backup(store: Path, host: str, stamp: str, config: str) -> tuple[Path | None, Path | None]:
    """Store config if changed. Returns (previous file, new file or None)."""
    existing = sorted(store.glob(f"{host}.*.cfg"))
    previous = existing[-1] if existing else None
    if previous and digest(previous.read_text(encoding="utf-8")) == digest(config):
        return previous, None
    name = f"{host}.{stamp.replace('-', '').replace(' ', 'T').replace(':', '')}.cfg"
    path = store / name
    atomic_write(path, config)
    return previous, path


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp)
        last_text = ""
        for stamp, text in FETCHES:
            text = last_text if text is None else text
            last_text = text
            previous, new = backup(store, "edge-sw02", stamp, text)
            if new is None:
                print(f"{stamp}: unchanged ({digest(text)[:12]}), nothing stored")
                continue
            print(f"{stamp}: stored {new.name} ({digest(text)[:12]})")
            if previous:
                diff = difflib.unified_diff(
                    previous.read_text(encoding="utf-8").splitlines(),
                    text.splitlines(),
                    fromfile=previous.name, tofile=new.name, lineterm="", n=1)
                for line in diff:
                    print("    " + line)
        print("stored:", ", ".join(p.name for p in sorted(store.glob("*.cfg"))))


if __name__ == "__main__":
    main()

# Output:
# 2026-09-14 02:00: stored edge-sw02.20260914T0200.cfg (38c9ecdc5946)
# 2026-09-15 02:00: stored edge-sw02.20260915T0200.cfg (043d390aa5f5)
#     --- edge-sw02.20260914T0200.cfg
#     +++ edge-sw02.20260915T0200.cfg
#     @@ -5,2 +5,3 @@
#      ! Last configuration change at 17:41:08 KST Fri Sep 11 2026 by netops
#     +! NVRAM config last updated at 23:10:44 KST Mon Sep 14 2026 by netops
#      !
# 2026-09-16 02:00: stored edge-sw02.20260916T0200.cfg (612669586bed)
#     --- edge-sw02.20260915T0200.cfg
#     +++ edge-sw02.20260916T0200.cfg
#     @@ -2,5 +2,5 @@
#
#     -Current configuration : 1873 bytes
#     +Current configuration : 1952 bytes
#      !
#     -! Last configuration change at 17:41:08 KST Fri Sep 11 2026 by netops
#     +! Last configuration change at 15:02:51 KST Tue Sep 15 2026 by kim
#      ! NVRAM config last updated at 23:10:44 KST Mon Sep 14 2026 by netops
#     @@ -16,3 +16,4 @@
#      interface GigabitEthernet1/0/6
#     - switchport access vlan 10
#     + description bk-nas02
#     + switchport access vlan 20
#       switchport mode access
#     @@ -20,2 +21,3 @@
#      ntp server 10.0.0.123
#     +ntp server 10.0.0.124
#      end
# 2026-09-17 02:00: unchanged (612669586bed), nothing stored
# stored: edge-sw02.20260914T0200.cfg, edge-sw02.20260915T0200.cfg, edge-sw02.20260916T0200.cfg
