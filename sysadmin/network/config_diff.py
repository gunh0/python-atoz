"""Running-config backup v2: ignore volatile lines, never print secrets in diffs

v1 stored a new copy whenever the fetched text changed, and IOS changes it
without anyone touching the config: "Current configuration : N bytes",
"! Last configuration change at ...", "! NVRAM config last updated ...",
"ntp clock-period". Nightly diffs full of those train people to ignore the
diff mail -- the one with a real change included.

v2 normalises before comparing: volatile lines are dropped for hashing and
diffing (the stored file is still the full, unmodified fetch). And because
diffs go to mail and tickets, secret values are replaced before printing:
"snmp-server community <secret sha256:1a2b3c4d>". Printing a short hash of
the old and new value still shows *that* a secret was rotated, and whether
two devices share one, without revealing it.
"""

import difflib
import hashlib
import os
import re
import tempfile
from pathlib import Path

VOLATILE = re.compile(r"^(Building configuration|Current configuration :|! Last configuration change"
                      r"|! NVRAM config last updated|ntp clock-period)")
SECRET = re.compile(r"^(\s*(?:username \S+(?: privilege \d+)? (?:secret|password) \d+|enable secret \d+"
                    r"|snmp-server community|key \d+|tacacs-server key \d+) )(\S+)(.*)$")

BASE = """\
Building configuration...

Current configuration : 1873 bytes
!
! Last configuration change at 17:41:08 KST Fri Sep 11 2026 by netops
!
version 16.9
hostname edge-sw02
!
username netops privilege 15 secret 9 $9$Lp2kQ0Zr8uXbN.$8sYpQnG0wbe1rT3x9aV
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
snmp-server community Rd0nly-2025 RO 99
ntp clock-period 36028797018963968
ntp server 10.0.0.123
end
"""

FETCHES = [
    ("2026-09-14 02:00", BASE),
    # nobody touched it: only header and clock-period moved
    ("2026-09-15 02:00", BASE.replace("! Last configuration change at 17:41:08 KST Fri Sep 11 2026 by netops\n",
                                      "! Last configuration change at 17:41:08 KST Fri Sep 11 2026 by netops\n"
                                      "! NVRAM config last updated at 23:10:44 KST Mon Sep 14 2026 by netops\n")
     .replace("36028797018963968", "36028797018963970")),
    # real change: port re-assigned, second NTP server, community rotated
    ("2026-09-16 02:00", BASE.replace("1873 bytes", "1952 bytes")
     .replace("17:41:08 KST Fri Sep 11 2026 by netops", "15:02:51 KST Tue Sep 15 2026 by kim")
     .replace(" switchport access vlan 10\n switchport mode access\n!\nsnmp",
              " description bk-nas02\n switchport access vlan 20\n switchport mode access\n!\nsnmp")
     .replace("Rd0nly-2025", "Rd0nly-2026")
     .replace("ntp server 10.0.0.123\n", "ntp server 10.0.0.123\nntp server 10.0.0.124\n")),
    ("2026-09-17 02:00", None),  # identical to previous fetch
]


def normalise(text: str) -> list[str]:
    return [line for line in text.splitlines() if not VOLATILE.match(line)]


def digest(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def mask(line: str) -> str:
    m = SECRET.match(line)
    if not m:
        return line
    tag = hashlib.sha256(m.group(2).encode("utf-8")).hexdigest()[:8]
    return f"{m.group(1)}<secret sha256:{tag}>{m.group(3)}"


def atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def backup(store: Path, host: str, stamp: str, config: str) -> tuple[Path | None, Path | None]:
    """Store config if it changed after normalising. Returns (previous, new or None)."""
    existing = sorted(store.glob(f"{host}.*.cfg"))
    previous = existing[-1] if existing else None
    if previous and digest(normalise(previous.read_text(encoding="utf-8"))) == digest(normalise(config)):
        return previous, None
    path = store / f"{host}.{stamp.replace('-', '').replace(' ', 'T').replace(':', '')}.cfg"
    atomic_write(path, config)  # full fetch, volatile lines included
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
                print(f"{stamp}: no meaningful change ({digest(normalise(text))[:12]}), nothing stored")
                continue
            print(f"{stamp}: stored {new.name} ({digest(normalise(text))[:12]})")
            if previous:
                old = [mask(l) for l in normalise(previous.read_text(encoding="utf-8"))]
                diff = difflib.unified_diff(old, [mask(l) for l in normalise(text)],
                                            fromfile=previous.name, tofile=new.name, lineterm="", n=1)
                for line in diff:
                    print("    " + line)
        print("stored:", ", ".join(p.name for p in sorted(store.glob("*.cfg"))))
        print("secret values left after masking:", any(s in "".join(mask(l) for l in BASE.splitlines())
                                               for s in ("Rd0nly", "$9$")))


if __name__ == "__main__":
    main()

# Output:
# 2026-09-14 02:00: stored edge-sw02.20260914T0200.cfg (7d8bab778ad3)
# 2026-09-15 02:00: no meaningful change (7d8bab778ad3), nothing stored
# 2026-09-16 02:00: stored edge-sw02.20260916T0200.cfg (ad6d66d2dba0)
#     --- edge-sw02.20260914T0200.cfg
#     +++ edge-sw02.20260916T0200.cfg
#     @@ -14,7 +14,9 @@
#      interface GigabitEthernet1/0/6
#     - switchport access vlan 10
#     + description bk-nas02
#     + switchport access vlan 20
#       switchport mode access
#      !
#     -snmp-server community <secret sha256:48bbc172> RO 99
#     +snmp-server community <secret sha256:989fadca> RO 99
#      ntp server 10.0.0.123
#     +ntp server 10.0.0.124
#      end
# 2026-09-17 02:00: no meaningful change (ad6d66d2dba0), nothing stored
# stored: edge-sw02.20260914T0200.cfg, edge-sw02.20260916T0200.cfg
# secret values left after masking: False
