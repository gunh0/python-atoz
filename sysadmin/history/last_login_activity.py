"""Login activity from `last` and `lastlog`: who logs in, from where, how long

`last` reads /var/log/wtmp (every session), `lastlog` reads /var/log/lastlog
(only the most recent login per account). Together they answer the audit
questions: which accounts are used, from which addresses, and which
accounts never or no longer log in and should be locked.

`last` has two parsing traps. Its columns are fixed width (user 8, tty 12,
host 16 characters) and the host is empty for console logins, so split on
offsets, not whitespace. And its timestamps have no year: the year comes
from the trailing "wtmp begins ..." line. Durations come from the "(hh:mm)"
suffix, which is correct even when the logout time is past midnight.

Ages are computed against a fixed report date, never "now", so the same
input always gives the same report.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta

REPORT_DATE = datetime(2026, 10, 5, 12, 0)
STALE_AFTER = timedelta(days=90)

LAST = """\
alice    pts/0        10.0.5.21        Mon Oct  5 09:12   still logged in
bob      pts/1        10.0.5.33        Mon Oct  5 08:47 - 11:02  (02:15)
root     tty1                          Sun Oct  4 23:59 - 00:03  (00:04)
reboot   system boot  6.8.0-45-generic Sun Oct  4 23:58   still running
alice    pts/0        10.0.5.21        Fri Oct  2 14:05 - 18:40  (04:35)
deploy   pts/2        10.0.9.4         Fri Oct  2 03:00 - 03:01  (00:01)
deploy   pts/2        10.0.9.4         Thu Oct  1 03:00 - 03:02  (00:02)
alice    pts/0        203.0.113.77     Thu Oct  1 22:41 - 23:15  (00:34)

wtmp begins Thu Oct  1 00:01:12 2026
"""

LASTLOG = """\
Username         Port     From             Latest
root             tty1                      Sun Oct  4 23:59:41 +0900 2026
daemon                                     **Never logged in**
alice            pts/0    10.0.5.21        Mon Oct  5 09:12:03 +0900 2026
bob              pts/1    10.0.5.33        Mon Oct  5 08:47:55 +0900 2026
deploy           pts/2    10.0.9.4         Fri Oct  2 03:00:02 +0900 2026
jlee             pts/3    10.0.5.40        Tue Jul 14 17:20:31 +0900 2026
svc-backup                                 **Never logged in**
oldadmin         pts/0    10.0.5.12        Mon Mar  2 10:03:44 +0900 2026
"""

INTERNAL = ("10.",)


def parse_last(text: str) -> list[dict]:
    year_line = next(l for l in text.splitlines() if l.startswith("wtmp begins"))
    year = int(year_line.split()[-1])
    sessions = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("wtmp begins"):
            continue
        user, tty, host, when, rest = (line[0:8].strip(), line[9:21].strip(), line[22:38].strip(),
                                       line[39:55], line[55:].strip())
        if user == "reboot":
            continue
        start = datetime.strptime(f"{when[4:]} {year}", "%b %d %H:%M %Y")
        m = re.search(r"\((\d+):(\d\d)\)$", rest)
        duration = timedelta(hours=int(m.group(1)), minutes=int(m.group(2))) if m else None
        sessions.append({"user": user, "tty": tty, "host": host or "(console)",
                         "start": start, "duration": duration, "open": "still logged in" in rest})
    return sessions


def parse_lastlog(text: str) -> dict[str, datetime | None]:
    latest = {}
    for line in text.splitlines()[1:]:
        user, stamp = line[:16].strip(), line[43:].strip()
        latest[user] = None if stamp == "**Never logged in**" else datetime.strptime(
            stamp, "%a %b %d %H:%M:%S %z %Y").replace(tzinfo=None)
    return latest


def main() -> None:
    sessions = parse_last(LAST)
    per_user: dict[str, list[dict]] = defaultdict(list)
    for s in sessions:
        per_user[s["user"]].append(s)

    print(f"{'user':<8} {'sessions':>8} {'total':>6}  last login        sources")
    for user, items in sorted(per_user.items()):
        total = sum((s["duration"] for s in items if s["duration"]), timedelta())
        hours, minutes = divmod(int(total.total_seconds()) // 60, 60)
        latest = max(s["start"] for s in items)
        sources = sorted({s["host"] for s in items})
        flag = "  <- external source" if any(not h.startswith(INTERNAL) and h != "(console)"
                                              for h in sources) else ""
        open_ = " (open)" if any(s["open"] for s in items) else ""
        print(f"{user:<8} {len(items):>8} {hours:>3}:{minutes:02d}  {latest:%Y-%m-%d %H:%M}  "
              f"{', '.join(sources)}{open_}{flag}")

    print()
    for user, when in parse_lastlog(LASTLOG).items():
        if when is None:
            print(f"{user:<11} never logged in")
        elif REPORT_DATE - when > STALE_AFTER:
            print(f"{user:<11} stale: last login {when:%Y-%m-%d}, {(REPORT_DATE - when).days} days ago")


if __name__ == "__main__":
    main()

# Output:
# user     sessions  total  last login        sources
# alice           3   5:09  2026-10-05 09:12  10.0.5.21, 203.0.113.77 (open)  <- external source
# bob             1   2:15  2026-10-05 08:47  10.0.5.33
# deploy          2   0:03  2026-10-02 03:00  10.0.9.4
# root            1   0:04  2026-10-04 23:59  (console)
#
# daemon      never logged in
# svc-backup  never logged in
# oldadmin    stale: last login 2026-03-02, 217 days ago
