"""IPMI SEL: turn `ipmitool sel elist` into incidents with durations

The System Event Log is the BMC's flight recorder: it keeps recording when
the OS is hung or powered off, which makes it the first thing to read after
an unexplained reboot. Raw, it is a list of Asserted/Deasserted lines; what
you want is "FAN3 was below critical from 02:11 to 03:01 (50 min)" and
"what is still asserted right now".

Details from real SELs: record IDs are hex; events logged before the BMC
clock was set show "Pre-Init" and a seconds-since-boot counter instead of a
date; the clock is the BMC's (usually UTC, sometimes whatever someone set);
memory events carry the DIMM in a sixth column; and a "Log area
reset/cleared" record means someone wiped the history -- worth flagging.
Also check `sel info`: a full SEL stops recording new events on many boards.
"""

from dataclasses import dataclass
from datetime import datetime

SEL_INFO = """\
SEL Information
Version          : 1.5 (v1.5, v2 compliant)
Entries          : 14
Percent Used     : 91%
Overflow         : false
"""

SEL_ELIST = """\
   1 | 09/10/2026 | 08:30:02 | Event Logging Disabled #0x07 | Log area reset/cleared | Asserted
   2 |  Pre-Init  |  0000000014 | System Event #0x83 | Timestamp Clock Sync | Asserted
   3 | 09/14/2026 | 02:11:40 | Fan FAN3 | Lower Critical going low  | Asserted
   4 | 09/14/2026 | 02:11:42 | Fan FAN3 | Lower Non-recoverable going low  | Asserted
   5 | 09/14/2026 | 02:14:05 | Temperature CPU2 Temp | Upper Non-critical going high | Asserted
   6 | 09/14/2026 | 02:58:47 | Fan FAN3 | Lower Non-recoverable going low  | Deasserted
   7 | 09/14/2026 | 03:01:12 | Fan FAN3 | Lower Critical going low  | Deasserted
   8 | 09/14/2026 | 04:20:00 | Power Supply PSU2 Status | Power Supply AC lost | Asserted
   9 | 09/14/2026 | 04:20:31 | Power Supply PSU2 Status | Power Supply AC lost | Deasserted
   a | 09/15/2026 | 11:47:09 | Memory #0x02 | Correctable ECC | Asserted | DIMM_B2
   b | 09/15/2026 | 12:30:51 | Memory #0x02 | Correctable ECC | Asserted | DIMM_B2
   c | 09/15/2026 | 13:02:55 | Memory #0x02 | Correctable ECC logging limit reached | Asserted | DIMM_B2
   d | 09/16/2026 | 06:40:13 | Memory #0x01 | Correctable ECC | Asserted | DIMM_A1
   e | 09/16/2026 | 09:15:00 | Fan FAN3 | Lower Critical going low  | Asserted
"""


@dataclass
class SelEvent:
    record: int
    when: datetime | None
    sensor: str
    event: str
    direction: str
    extra: str


def parse_elist(text: str) -> list[SelEvent]:
    events = []
    for line in text.splitlines():
        cols = [c.strip() for c in line.split("|")]
        if len(cols) < 6:
            continue
        record = int(cols[0], 16)
        when = None if cols[1] == "Pre-Init" else datetime.strptime(f"{cols[1]} {cols[2]}",
                                                                    "%m/%d/%Y %H:%M:%S")
        extra = cols[6] if len(cols) > 6 else ""
        events.append(SelEvent(record, when, cols[3], cols[4], cols[5], extra))
    return events


# One-shot records: they are never deasserted, so they are not incidents.
# Memory ECC events are counts per DIMM and are summarised separately.
ONE_SHOT = ("Event Logging Disabled", "System Event", "Memory")


def incidents(events: list[SelEvent]):
    """Pair each Asserted with the next Deasserted of the same sensor+event."""
    open_: dict[tuple[str, str], SelEvent] = {}
    closed = []
    for ev in events:
        if ev.sensor.startswith(ONE_SHOT):
            continue
        key = (ev.sensor, ev.event)
        if ev.direction == "Asserted" and key not in open_:
            open_[key] = ev
        elif ev.direction == "Deasserted" and key in open_:
            closed.append((open_.pop(key), ev))
    return closed, list(open_.values())


def main() -> None:
    info = {k.strip(): v.strip() for k, v in (l.split(":", 1) for l in SEL_INFO.splitlines() if ":" in l)}
    used = int(info["Percent Used"].rstrip("%"))
    if used >= 80:
        print(f"WARNING SEL {used}% full: save it (sel save) and clear it, or new events are lost")

    events = parse_elist(SEL_ELIST)
    for ev in events:
        if ev.event == "Log area reset/cleared":
            print(f"NOTICE  SEL was cleared at {ev.when:%Y-%m-%d %H:%M} (record {ev.record:#x})")
        if ev.when is None:
            print(f"NOTICE  record {ev.record:#x} has no wall-clock time (Pre-Init): {ev.event}")

    closed, still_open = incidents(events)
    print()
    print("resolved:")
    for start, end in sorted(closed, key=lambda pair: pair[0].record):
        assert start.when and end.when
        minutes = (end.when - start.when).total_seconds() / 60
        print(f"  {start.when:%m-%d %H:%M:%S} {start.sensor:<25} {start.event:<34} {minutes:5.1f} min")

    print("still asserted:")
    for ev in still_open:
        print(f"  {ev.when:%m-%d %H:%M:%S} {ev.sensor:<25} {ev.event}")

    print("memory:")
    for dimm in sorted({ev.extra for ev in events if ev.sensor.startswith("Memory")}):
        mine = [ev for ev in events if ev.extra == dimm]
        limit = any("limit reached" in ev.event for ev in mine)
        mine = [ev for ev in mine if ev.event == "Correctable ECC"]
        note = "  logging limit reached: real count is higher, replace DIMM" if limit else ""
        print(f"  {dimm}: {len(mine)} ECC records{note}")


if __name__ == "__main__":
    main()

# Output:
# WARNING SEL 91% full: save it (sel save) and clear it, or new events are lost
# NOTICE  SEL was cleared at 2026-09-10 08:30 (record 0x1)
# NOTICE  record 0x2 has no wall-clock time (Pre-Init): Timestamp Clock Sync
#
# resolved:
#   09-14 02:11:40 Fan FAN3                  Lower Critical going low            49.5 min
#   09-14 02:11:42 Fan FAN3                  Lower Non-recoverable going low     47.1 min
#   09-14 04:20:00 Power Supply PSU2 Status  Power Supply AC lost                 0.5 min
# still asserted:
#   09-14 02:14:05 Temperature CPU2 Temp     Upper Non-critical going high
#   09-16 09:15:00 Fan FAN3                  Lower Critical going low
# memory:
#   DIMM_A1: 1 ECC records
#   DIMM_B2: 2 ECC records  logging limit reached: real count is higher, replace DIMM
