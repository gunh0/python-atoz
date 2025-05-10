"""Shell history with HISTTIMEFORMAT: '#<epoch>' lines, sessions, night work

With HISTTIMEFORMAT set, bash writes a comment line "#1789344131" before each
entry in ~/.bash_history. The epoch is UTC seconds; the timezone you show it
in is a choice, and it must be an explicit one. `datetime.fromtimestamp(ts)`
without tz uses the machine's local zone, so the same report reads 09:02 on
the Seoul jump host and 00:02 on a UTC CI runner. Here the zone is pinned
(fixed +09:00 offset; zoneinfo("Asia/Seoul") is equivalent since Korea has
no DST).

Parsing rules that matter on real files: lines before the first timestamp
come from before HISTTIMEFORMAT was enabled and have no time; an entry may
span several lines (multi-line commands with `shopt -s lithist`); and only
'#' followed by digits only is a timestamp, a plain comment line is a command.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9), "KST")
SESSION_GAP = timedelta(minutes=30)

HISTORY = """\
uptime
ls /etc/cron.d
#1789344131
sudo -i
#1789344170
systemctl list-timers
#1789344302
journalctl -u backup.service -n 100
#1789344390
vim /etc/systemd/system/backup.timer
#1789344501
systemctl daemon-reload
#1789360800
for h in web01 web02 web03; do
  ssh "$h" 'df -h /var'
done
#1789360912
# check again after cleanup
#1789361030
ssh web02 'sudo journalctl --vacuum-size=500M'
#1789406220
sudo systemctl restart postgresql
#1789406281
tail -n 50 /var/log/postgresql/postgresql-16-main.log
#1789406440
exit
"""


@dataclass
class Entry:
    when: datetime | None
    command: str


def parse_history(text: str) -> list[Entry]:
    entries: list[Entry] = []
    pending: datetime | None = None
    in_entry = False
    for line in text.splitlines():
        if line.startswith("#") and line[1:].isdigit():
            pending = datetime.fromtimestamp(int(line[1:]), tz=KST)
            in_entry = False
        elif in_entry and pending is not None:
            entries[-1].command += "\n" + line  # continuation of a multi-line entry
        else:
            entries.append(Entry(pending, line))
            in_entry = pending is not None
    return entries


def sessions(entries: list[Entry]) -> list[list[Entry]]:
    grouped: list[list[Entry]] = []
    last: datetime | None = None
    for entry in entries:
        if entry.when is None:
            continue
        if last is None or entry.when - last > SESSION_GAP:
            grouped.append([])
        grouped[-1].append(entry)
        last = entry.when
    return grouped


def main() -> None:
    entries = parse_history(HISTORY)
    print(f"{len(entries)} entries, {sum(e.when is None for e in entries)} without timestamp")
    print()
    for entry in entries:
        stamp = entry.when.strftime("%Y-%m-%d %H:%M:%S %Z") if entry.when else "(no time)".ljust(23)
        first, *more = entry.command.splitlines()
        suffix = f"  [+{len(more)} lines]" if more else ""
        print(f"{stamp}  {first}{suffix}")

    print()
    for n, group in enumerate(sessions(entries), start=1):
        start, end = group[0].when, group[-1].when
        assert start and end
        night = " (night: 00-06)" if start.hour < 6 else ""
        print(f"session {n}: {start:%m-%d %H:%M}-{end:%H:%M} {len(group)} commands{night}")

    first = next(e for e in entries if e.when)
    assert first.when
    print()
    print("same instant, explicit zones:",
          first.when.strftime("%H:%M %Z"), "=", first.when.astimezone(timezone.utc).strftime("%H:%M %Z"))


if __name__ == "__main__":
    main()

# Output:
# 13 entries, 2 without timestamp
#
# (no time)                uptime
# (no time)                ls /etc/cron.d
# 2026-09-14 09:02:11 KST  sudo -i
# 2026-09-14 09:02:50 KST  systemctl list-timers
# 2026-09-14 09:05:02 KST  journalctl -u backup.service -n 100
# 2026-09-14 09:06:30 KST  vim /etc/systemd/system/backup.timer
# 2026-09-14 09:08:21 KST  systemctl daemon-reload
# 2026-09-14 13:40:00 KST  for h in web01 web02 web03; do  [+2 lines]
# 2026-09-14 13:41:52 KST  # check again after cleanup
# 2026-09-14 13:43:50 KST  ssh web02 'sudo journalctl --vacuum-size=500M'
# 2026-09-15 02:17:00 KST  sudo systemctl restart postgresql
# 2026-09-15 02:18:01 KST  tail -n 50 /var/log/postgresql/postgresql-16-main.log
# 2026-09-15 02:20:40 KST  exit
#
# session 1: 09-14 09:02-09:08 5 commands
# session 2: 09-14 13:40-13:43 3 commands
# session 3: 09-15 02:17-02:20 3 commands (night: 00-06)
#
# same instant, explicit zones: 09:02 KST = 00:02 UTC
