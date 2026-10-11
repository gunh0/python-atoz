"""Login activity v2: `last` across a year boundary, crashes and lost sessions

v1 took the year from "wtmp begins" and read durations as "(hh:mm)". The
first January report broke both assumptions:

- wtmp began in December, so every January login was dated a year early
  and the "last login" column went backwards. `last` prints newest first;
  walk it oldest-first and add a year whenever the month goes down.
- sessions longer than a day print "(1+03:15)"; v1's regex did not match
  and silently counted them as zero.
- the end of a session is not always a logout: "- crash" (the host went
  down without a clean shutdown), "- down" (clean shutdown), "gone - no
  logout" (the session's process vanished, typical after an OOM kill or a
  dropped SSH connection). Those are exactly the lines an incident review
  wants, so they are reported, together with the reboot records.

Ages are still computed against a fixed report date, never "now".
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta

REPORT_DATE = datetime(2026, 1, 5, 12, 0)
STALE_AFTER = timedelta(days=90)

LAST = """\
alice    pts/0        10.0.5.21        Mon Jan  5 09:12  still logged in
reboot   system boot  6.8.0-49-generic Sun Jan  4 08:02  still running
bob      pts/1        10.0.5.33        Sat Jan  3 22:10 - crash  (09:52)
deploy   pts/2        10.0.9.4         Sat Jan  3 03:00 - 03:01  (00:01)
alice    pts/0        10.0.5.21        Fri Jan  2 09:30 - 18:05  (08:35)
reboot   system boot  6.8.0-49-generic Thu Jan  1 09:00 - 08:02 (2+23:02)
root     tty1                          Wed Dec 31 23:50 - down   (00:07)
alice    pts/0        10.0.5.21        Tue Dec 30 14:20 - 17:35 (1+03:15)
carol    pts/3        203.0.113.77     Mon Dec 29 10:00   gone - no logout

wtmp begins Mon Dec 29 00:01:12 2025
"""

LASTLOG = """\
Username         Port     From             Latest
root             tty1                      Wed Dec 31 23:50:12 +0900 2025
daemon                                     **Never logged in**
alice            pts/0    10.0.5.21        Mon Jan  5 09:12:03 +0900 2026
bob              pts/1    10.0.5.33        Sat Jan  3 22:10:40 +0900 2026
carol            pts/3    203.0.113.77     Mon Dec 29 10:00:19 +0900 2025
deploy           pts/2    10.0.9.4         Sat Jan  3 03:00:02 +0900 2026
jlee             pts/3    10.0.5.40        Wed Oct 15 17:20:31 +0900 2025
svc-backup                                 **Never logged in**
oldadmin         pts/0    10.0.5.12        Mon Jun  2 10:03:44 +0900 2025
"""

INTERNAL = ("10.",)
DURATION = re.compile(r"\((?:(\d+)\+)?(\d+):(\d\d)\)$")


def parse_duration(rest: str) -> timedelta | None:
    m = DURATION.search(rest)
    if not m:
        return None
    days, hours, minutes = int(m.group(1) or 0), int(m.group(2)), int(m.group(3))
    return timedelta(days=days, hours=hours, minutes=minutes)


def end_reason(rest: str) -> str:
    for marker, reason in (("still logged in", "open"), ("still running", "running"),
                           ("gone - no logout", "gone"), ("- crash", "crash"), ("- down", "shutdown")):
        if marker in rest:
            return reason
    return "logout"


def parse_last(text: str) -> list[dict]:
    lines = [l for l in text.splitlines() if l.strip()]
    begins = next(l for l in lines if l.startswith("wtmp begins"))
    year = int(begins.split()[-1])
    previous_month = datetime.strptime(begins.split()[3], "%b").month
    records = []
    for line in reversed([l for l in lines if not l.startswith("wtmp begins")]):  # oldest first
        user, tty, host, when, rest = (line[0:8].strip(), line[9:21].strip(), line[22:38].strip(),
                                       line[39:55], line[55:].strip())
        month = datetime.strptime(when[4:7], "%b").month
        if month < previous_month:
            year += 1  # crossed new year's eve
        previous_month = month
        start = datetime.strptime(f"{when[4:]} {year}", "%b %d %H:%M %Y")
        records.append({"user": user, "tty": tty, "host": host or "(console)", "start": start,
                        "duration": parse_duration(rest), "end": end_reason(rest)})
    return records[::-1]  # back to newest first, like `last`


def parse_lastlog(text: str) -> dict[str, datetime | None]:
    latest = {}
    for line in text.splitlines()[1:]:
        user, stamp = line[:16].strip(), line[43:].strip()
        latest[user] = None if stamp == "**Never logged in**" else datetime.strptime(
            stamp, "%a %b %d %H:%M:%S %z %Y").replace(tzinfo=None)
    return latest


def hhmm(delta: timedelta) -> str:
    hours, minutes = divmod(int(delta.total_seconds()) // 60, 60)
    return f"{hours:>3}:{minutes:02d}"


def main() -> None:
    records = parse_last(LAST)
    sessions = [r for r in records if r["user"] != "reboot"]
    per_user: dict[str, list[dict]] = defaultdict(list)
    for s in sessions:
        per_user[s["user"]].append(s)

    wtmp_year = int(LAST.rstrip().split()[-1])
    later = sum(r["start"].year > wtmp_year for r in records)
    print(f"{later} of {len(records)} records fall after new year (wtmp begins in {wtmp_year})")
    print()
    print(f"{'user':<8} {'sessions':>8} {'total':>6}  last login        sources")
    for user, items in sorted(per_user.items()):
        total = sum((s["duration"] for s in items if s["duration"]), timedelta())
        latest = max(s["start"] for s in items)
        sources = sorted({s["host"] for s in items})
        external = any(not h.startswith(INTERNAL) and h != "(console)" for h in sources)
        flag = "  <- external source" if external else ""
        unknown = "?" if any(s["end"] == "gone" for s in items) else " "  # no end time recorded
        print(f"{user:<8} {len(items):>8} {hhmm(total)}{unknown} {latest:%Y-%m-%d %H:%M}  "
              f"{', '.join(sources)}{flag}")

    print()
    for r in records:
        if r["user"] == "reboot":
            up = "still running" if r["end"] == "running" else f"up {hhmm(r['duration']).strip()} h"
            print(f"boot     {r['start']:%Y-%m-%d %H:%M}  kernel {r['host']}, {up}")
        elif r["end"] in ("crash", "gone", "shutdown"):
            print(f"{r['end']:<8} {r['start']:%Y-%m-%d %H:%M}  {r['user']} on {r['tty']} from {r['host']}")

    print()
    for user, when in parse_lastlog(LASTLOG).items():
        if when is None:
            print(f"{user:<11} never logged in")
        elif REPORT_DATE - when > STALE_AFTER:
            print(f"{user:<11} stale: last login {when:%Y-%m-%d}, {(REPORT_DATE - when).days} days ago")


if __name__ == "__main__":
    main()

# Output:
# 6 of 9 records fall after new year (wtmp begins in 2025)
#
# user     sessions  total  last login        sources
# alice           3  35:50  2026-01-05 09:12  10.0.5.21
# bob             1   9:52  2026-01-03 22:10  10.0.5.33
# carol           1   0:00? 2025-12-29 10:00  203.0.113.77  <- external source
# deploy          1   0:01  2026-01-03 03:00  10.0.9.4
# root            1   0:07  2025-12-31 23:50  (console)
#
# boot     2026-01-04 08:02  kernel 6.8.0-49-generic, still running
# crash    2026-01-03 22:10  bob on pts/1 from 10.0.5.33
# boot     2026-01-01 09:00  kernel 6.8.0-49-generic, up 71:02 h
# shutdown 2025-12-31 23:50  root on tty1 from (console)
# gone     2025-12-29 10:00  carol on pts/3 from 203.0.113.77
#
# daemon      never logged in
# svc-backup  never logged in
# oldadmin    stale: last login 2025-06-02, 217 days ago
