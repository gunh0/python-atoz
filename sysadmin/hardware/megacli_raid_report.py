"""MegaCLI RAID report v2: virtual drives, physical disk errors and rebuilds

LSI/Broadcom MegaRAID controllers are still everywhere in older racks, and the
only interface many of them have is MegaCli64, whose output is a loose list of
"Key : Value" lines grouped under "Virtual Drive:" headers. A cron job that
greps for "Degraded" works until the day a drive is "Partially Degraded" or
the controller reports "Offline", so parse the whole block into a record and
decide on the State field explicitly.

The parser below splits on the first ':' only (sizes and names may contain
more colons), normalises keys, and starts a new record at every
"Virtual Drive:" line. Anything other than "Optimal" is treated as a problem.

v2 also reads `-PDList -aALL`. "Degraded" alone does not tell you how bad it
is: a RAID-5 that is rebuilding onto a fresh disk while another member keeps
growing Media Error / Predictive Failure counts is one bad sector away from
losing the array. Media errors are the disk; Other Error Count is usually the
path (cable, backplane, expander) and is reported separately.
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

PDLIST = """\

Adapter #0

Enclosure Device ID: 32
Slot Number: 0
Drive's position: DiskGroup: 0, Span: 0, Arm: 0
Media Error Count: 0
Other Error Count: 0
Predictive Failure Count: 0
Raw Size: 279.396 GB [0x22ecb25c Sectors]
Firmware state: Online, Spun Up
Inquiry Data: SEAGATE ST300MM0048     N004S0K2B1QX
Enclosure Device ID: 32
Slot Number: 1
Drive's position: DiskGroup: 0, Span: 0, Arm: 1
Media Error Count: 0
Other Error Count: 0
Predictive Failure Count: 0
Raw Size: 279.396 GB [0x22ecb25c Sectors]
Firmware state: Online, Spun Up
Inquiry Data: SEAGATE ST300MM0048     N004S0K2B7RD
Enclosure Device ID: 32
Slot Number: 2
Drive's position: DiskGroup: 1, Span: 0, Arm: 0
Media Error Count: 0
Other Error Count: 0
Predictive Failure Count: 0
Raw Size: 1.819 TB [0xe8e088b0 Sectors]
Firmware state: Rebuild
Inquiry Data: SEAGATE ST2000NM0055    SN05ZC20QW1L
Enclosure Device ID: 32
Slot Number: 3
Drive's position: DiskGroup: 1, Span: 0, Arm: 1
Media Error Count: 14
Other Error Count: 0
Predictive Failure Count: 1
Raw Size: 1.819 TB [0xe8e088b0 Sectors]
Firmware state: Online, Spun Up
Inquiry Data: SEAGATE ST2000NM0055    SN05ZC1XK4PA
Enclosure Device ID: 32
Slot Number: 4
Drive's position: DiskGroup: 1, Span: 0, Arm: 2
Media Error Count: 0
Other Error Count: 3
Predictive Failure Count: 0
Raw Size: 1.819 TB [0xe8e088b0 Sectors]
Firmware state: Online, Spun Up
Inquiry Data: SEAGATE ST2000NM0055    SN05ZC1XM9TT
Enclosure Device ID: 32
Slot Number: 5
Drive's position: DiskGroup: 1, Span: 0, Arm: 3
Media Error Count: 0
Other Error Count: 0
Predictive Failure Count: 0
Raw Size: 1.819 TB [0xe8e088b0 Sectors]
Firmware state: Online, Spun Up
Inquiry Data: SEAGATE ST2000NM0055    SN05ZC1XN2EE
Enclosure Device ID: 32
Slot Number: 6
Drive's position: DiskGroup: 2, Span: 0, Arm: 0
Media Error Count: 0
Other Error Count: 0
Predictive Failure Count: 0
Raw Size: 931.512 GB [0x74706db0 Sectors]
Firmware state: Online, Spun Up
Inquiry Data: SEAGATE ST1000NX0423    SN04W1T7H2LA
Enclosure Device ID: 32
Slot Number: 7
Drive's position: DiskGroup: 2, Span: 0, Arm: 1
Media Error Count: 0
Other Error Count: 1
Predictive Failure Count: 0
Raw Size: 931.512 GB [0x74706db0 Sectors]
Firmware state: Online, Spun Up
Inquiry Data: SEAGATE ST1000NX0423    SN04W1T7J5QE
Enclosure Device ID: 32
Slot Number: 8
Drive's position: DiskGroup: 2, Span: 1, Arm: 0
Media Error Count: 0
Other Error Count: 0
Predictive Failure Count: 0
Raw Size: 931.512 GB [0x74706db0 Sectors]
Firmware state: Online, Spun Up
Inquiry Data: SEAGATE ST1000NX0423    SN04W1T7K8UU
Enclosure Device ID: 32
Slot Number: 9
Drive's position: DiskGroup: 2, Span: 1, Arm: 1
Media Error Count: 0
Other Error Count: 0
Predictive Failure Count: 0
Raw Size: 931.512 GB [0x74706db0 Sectors]
Firmware state: Online, Spun Up
Inquiry Data: SEAGATE ST1000NX0423    SN04W1T7L1ZC

Exit Code: 0x00
"""

# `MegaCli64 -PDRbld -ShowProg -PhysDrv [32:2] -a0`
REBUILD_PROGRESS = """\

Rebuild Progress on Device at Enclosure 32, Slot 2 Completed 47% in 38 Minutes.

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


@dataclass
class PhysicalDrive:
    adapter: int
    fields: dict[str, str]

    @property
    def slot(self) -> str:
        return f"{self.fields['enclosure_device_id']}:{self.fields['slot_number']}"

    @property
    def disk_group(self) -> int:
        # "DiskGroup: 1, Span: 0, Arm: 2" -- the value itself contains colons
        return int(self.fields["drive's_position"].split(",")[0].split(":")[1])

    @property
    def state(self) -> str:
        return self.fields["firmware_state"].split(",")[0]

    def count(self, name: str) -> int:
        return int(self.fields.get(name, "0"))


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


def parse_pdlist(text: str) -> list[PhysicalDrive]:
    disks: list[PhysicalDrive] = []
    adapter = -1
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Adapter #"):
            adapter = int(line[len("Adapter #"):])
        elif line.startswith("Enclosure Device ID:"):
            disks.append(PhysicalDrive(adapter, {}))
        if line.startswith("Exit Code:"):
            break
        if ":" in line and disks:
            key, value = line.split(":", 1)
            disks[-1].fields[normalise_key(key)] = value.strip()
    return disks


def parse_rebuild(text: str) -> dict[str, tuple[int, int]]:
    """'... Enclosure 32, Slot 2 Completed 47% in 38 Minutes.' -> {'32:2': (47, 38)}"""
    progress = {}
    for line in text.splitlines():
        words = line.replace(",", "").rstrip(".").split()
        if line.startswith("Rebuild Progress") and "Completed" in words:
            slot = f"{words[words.index('Enclosure') + 1]}:{words[words.index('Slot') + 1]}"
            percent = int(words[words.index("Completed") + 1].rstrip("%"))
            minutes = int(words[words.index("in") + 1])
            progress[slot] = (percent, minutes)
    return progress


def disk_findings(pd: PhysicalDrive) -> list[str]:
    found = []
    if pd.state not in ("Online", "Hotspare", "Unconfigured(good)"):
        found.append(f"state {pd.state}")
    if pd.count("media_error_count"):
        found.append(f"{pd.count('media_error_count')} media errors")
    if pd.count("predictive_failure_count"):
        found.append("predictive failure (SMART trip)")
    if pd.count("other_error_count"):
        found.append(f"{pd.count('other_error_count')} other errors (check cable/backplane)")
    return found


def main() -> None:
    drives = parse_ldinfo(LDINFO)
    disks = parse_pdlist(PDLIST)
    rebuilds = parse_rebuild(REBUILD_PROGRESS)
    print(f"{'VD':<7} {'name':<8} {'level':<8} {'size':>10}  state")
    for vd in drives:
        name = vd.fields.get("name", "")
        size = vd.fields.get("size", "")
        print(f"a{vd.adapter}/v{vd.number:<3} {name:<8} {vd.raid_level:<8} {size:>10}  {vd.state}")

    print()
    print(f"{'slot':<6} {'dg':>2}  {'state':<8} {'media':>5} {'other':>5} {'pred':>4}  model")
    for pd in disks:
        model = " ".join(pd.fields["inquiry_data"].split()[:2])
        print(f"{pd.slot:<6} {pd.disk_group:>2}  {pd.state:<8} {pd.count('media_error_count'):>5} "
              f"{pd.count('other_error_count'):>5} {pd.count('predictive_failure_count'):>4}  {model}")

    problems = [vd for vd in drives if vd.state != "Optimal"]
    print()
    for vd in problems:
        cache = vd.fields.get("current_cache_policy", "").split(",")[0]
        print(f"PROBLEM a{vd.adapter}/v{vd.number} ({vd.fields.get('name')}): state={vd.state}, "
              f"current cache={cache}")
        # DiskGroup equals the VD number when each group carries one VD, as here;
        # `-LdPdInfo` is the authoritative mapping when groups are shared.
        members = [pd for pd in disks if pd.adapter == vd.adapter and pd.disk_group == vd.number]
        for pd in members:
            notes = disk_findings(pd)
            if pd.slot in rebuilds:
                percent, minutes = rebuilds[pd.slot]
                eta = round(minutes * (100 - percent) / percent)
                notes.append(f"rebuild {percent}% after {minutes} min, ~{eta} min left")
            if notes:
                print(f"  disk {pd.slot}: " + "; ".join(notes))
        rebuilding = any(pd.state == "Rebuild" for pd in members)
        at_risk = [pd.slot for pd in members if pd.state == "Online" and
                   (pd.count("media_error_count") or pd.count("predictive_failure_count"))]
        if rebuilding and at_risk and vd.raid_level == "RAID-5":
            print(f"  RISK: RAID-5 rebuild depends on {', '.join(at_risk)}, which is already failing;"
                  " verify backups before anything else")

    # Disks outside a problem VD still deserve a ticket.
    quiet = [pd for pd in disks if disk_findings(pd)
             and not any(vd.number == pd.disk_group for vd in problems)]
    for pd in quiet:
        print(f"NOTICE disk {pd.slot} (dg {pd.disk_group}): " + "; ".join(disk_findings(pd)))
    print(f"{len(drives)} virtual drives, {len(problems)} not optimal, {len(disks)} disks")


if __name__ == "__main__":
    main()

# Output:
# VD      name     level          size  state
# a0/v0   os       RAID-1   278.875 GB  Optimal
# a0/v1   data     RAID-5     5.457 TB  Degraded
# a0/v2   db       RAID-10    1.817 TB  Optimal
#
# slot   dg  state    media other pred  model
# 32:0    0  Online       0     0    0  SEAGATE ST300MM0048
# 32:1    0  Online       0     0    0  SEAGATE ST300MM0048
# 32:2    1  Rebuild      0     0    0  SEAGATE ST2000NM0055
# 32:3    1  Online      14     0    1  SEAGATE ST2000NM0055
# 32:4    1  Online       0     3    0  SEAGATE ST2000NM0055
# 32:5    1  Online       0     0    0  SEAGATE ST2000NM0055
# 32:6    2  Online       0     0    0  SEAGATE ST1000NX0423
# 32:7    2  Online       0     1    0  SEAGATE ST1000NX0423
# 32:8    2  Online       0     0    0  SEAGATE ST1000NX0423
# 32:9    2  Online       0     0    0  SEAGATE ST1000NX0423
#
# PROBLEM a0/v1 (data): state=Degraded, current cache=WriteThrough
#   disk 32:2: state Rebuild; rebuild 47% after 38 min, ~43 min left
#   disk 32:3: 14 media errors; predictive failure (SMART trip)
#   disk 32:4: 3 other errors (check cable/backplane)
#   RISK: RAID-5 rebuild depends on 32:3, which is already failing; verify backups before anything else
# NOTICE disk 32:7 (dg 2): 1 other errors (check cable/backplane)
# 3 virtual drives, 1 not optimal, 10 disks
