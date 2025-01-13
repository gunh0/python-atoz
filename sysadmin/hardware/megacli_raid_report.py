"""MegaCLI RAID report: virtual drive state from `MegaCli64 -LDInfo -Lall -aALL`

LSI/Broadcom MegaRAID controllers are still everywhere in older racks, and the
only interface many of them have is MegaCli64, whose output is a loose list of
"Key : Value" lines grouped under "Virtual Drive:" headers. A cron job that
greps for "Degraded" works until the day a drive is "Partially Degraded" or
the controller reports "Offline", so parse the whole block into a record and
decide on the State field explicitly.

The parser below splits on the first ':' only (sizes and names may contain
more colons), normalises keys, and starts a new record at every
"Virtual Drive:" line. Anything other than "Optimal" is treated as a problem.
"""

from dataclasses import dataclass

LDINFO = """\

Adapter 0 -- Virtual Drive Information:
Virtual Drive: 0 (Target Id: 0)
Name                :os
RAID Level          : Primary-1, Secondary-0, RAID Level Qualifier-0
Size                : 278.875 GB
Sector Size         : 512
State               : Optimal
Strip Size          : 64 KB
Number Of Drives    : 2
Span Depth          : 1
Default Cache Policy: WriteBack, ReadAhead, Direct, No Write Cache if Bad BBU
Current Cache Policy: WriteBack, ReadAhead, Direct, No Write Cache if Bad BBU
Disk Cache Policy   : Disk's Default
Virtual Drive: 1 (Target Id: 1)
Name                :data
RAID Level          : Primary-5, Secondary-0, RAID Level Qualifier-3
Size                : 5.457 TB
Sector Size         : 512
State               : Degraded
Strip Size          : 256 KB
Number Of Drives    : 4
Span Depth          : 1
Default Cache Policy: WriteBack, ReadAhead, Direct, No Write Cache if Bad BBU
Current Cache Policy: WriteThrough, ReadAhead, Direct, No Write Cache if Bad BBU
Disk Cache Policy   : Disabled
Virtual Drive: 2 (Target Id: 2)
Name                :db
RAID Level          : Primary-1, Secondary-0, RAID Level Qualifier-0
Size                : 1.817 TB
Sector Size         : 512
State               : Optimal
Strip Size          : 64 KB
Number Of Drives per span:2
Span Depth          : 2
Default Cache Policy: WriteBack, ReadAhead, Direct, No Write Cache if Bad BBU
Current Cache Policy: WriteBack, ReadAhead, Direct, No Write Cache if Bad BBU
Disk Cache Policy   : Disk's Default

Exit Code: 0x00
"""


@dataclass
class VirtualDrive:
    adapter: int
    number: int
    fields: dict[str, str]

    @property
    def state(self) -> str:
        return self.fields.get("state", "Unknown")

    @property
    def raid_level(self) -> str:
        # "Primary-1, Secondary-0, RAID Level Qualifier-0": the primary level is
        # what people mean, and a RAID-1 spanned more than once is RAID-10.
        parts = dict(p.strip().rsplit("-", 1) for p in self.fields.get("raid_level", "").split(","))
        primary = parts.get("Primary", "?")
        if primary == "1" and int(self.fields.get("span_depth", "1")) > 1:
            return "RAID-10"
        return f"RAID-{primary}"


def normalise_key(key: str) -> str:
    return "_".join(key.strip().lower().split())


def parse_ldinfo(text: str) -> list[VirtualDrive]:
    drives: list[VirtualDrive] = []
    adapter = -1
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Adapter ") and "Virtual Drive Information" in line:
            adapter = int(line.split()[1])
        elif line.startswith("Virtual Drive:"):
            number = int(line.split(":", 1)[1].split()[0])
            drives.append(VirtualDrive(adapter, number, {}))
        elif line.startswith("Exit Code:"):
            break
        elif ":" in line and drives:
            key, value = line.split(":", 1)
            drives[-1].fields[normalise_key(key)] = value.strip()
    return drives


def main() -> None:
    drives = parse_ldinfo(LDINFO)
    print(f"{'VD':<7} {'name':<8} {'level':<8} {'size':>10}  state")
    for vd in drives:
        name = vd.fields.get("name", "")
        size = vd.fields.get("size", "")
        print(f"a{vd.adapter}/v{vd.number:<3} {name:<8} {vd.raid_level:<8} {size:>10}  {vd.state}")

    problems = [vd for vd in drives if vd.state != "Optimal"]
    print()
    for vd in problems:
        cache = vd.fields.get("current_cache_policy", "").split(",")[0]
        print(f"PROBLEM a{vd.adapter}/v{vd.number} ({vd.fields.get('name')}): state={vd.state}, "
              f"current cache={cache}")
    print(f"{len(drives)} virtual drives, {len(problems)} not optimal")


if __name__ == "__main__":
    main()

# Output:
# VD      name     level          size  state
# a0/v0   os       RAID-1   278.875 GB  Optimal
# a0/v1   data     RAID-5     5.457 TB  Degraded
# a0/v2   db       RAID-10    1.817 TB  Optimal
#
# PROBLEM a0/v1 (data): state=Degraded, current cache=WriteThrough
# 3 virtual drives, 1 not optimal
