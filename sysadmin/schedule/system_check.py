"""Periodic system check that writes a report — thresholds, atomic files, state changes

The small script every server ends up with: every 15 minutes look at load,
memory and disk, write a report a human or a dashboard can read, and say
something only when the state changes. Three habits make it trustworthy:

- Each metric has WARN and CRIT thresholds, and the report status is the
  worst of them, with the Nagios exit codes (0 OK, 1 WARN, 2 CRIT) so a
  monitoring agent can run the same script.
- The report is written to a temporary file in the same directory and
  moved into place with os.replace(), which is atomic: a reader never sees
  half a report, even if the disk fills up mid-write.
- Notifications fire on state change only (OK -> WARN, WARN -> CRIT, back
  to OK), not on every run, or people learn to ignore them.

The collectors take the text of /proc/loadavg, /proc/meminfo and `df -P`;
the demo feeds three embedded snapshots of a host getting worse, and runs
the checks with sched on a fake clock, so the reports are reproducible.
"""

import datetime as dt
import os
import sched
import tempfile
from pathlib import Path

CPUS = 4
SNAPSHOTS = [
    {"loadavg": "0.42 0.38 0.30 1/412 9921",
     "meminfo": "MemTotal: 8048232 kB\nMemAvailable: 4910020 kB\n",
     "df": "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
           "/dev/vda1 51475068 36547298 14927770 71% /\n/dev/vdb1 206292664 70139505 136153159 34% /srv\n"},
    {"loadavg": "5.21 3.90 2.10 7/430 10233",
     "meminfo": "MemTotal: 8048232 kB\nMemAvailable: 1770611 kB\n",
     "df": "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
           "/dev/vda1 51475068 44268558 7206510 86% /\n/dev/vdb1 206292664 70241002 136051662 35% /srv\n"},
    {"loadavg": "9.84 7.12 4.40 12/451 10871",
     "meminfo": "MemTotal: 8048232 kB\nMemAvailable: 482894 kB\n",
     "df": "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
           "/dev/vda1 51475068 49416065 2059003 96% /\n/dev/vdb1 206292664 70300100 135992564 35% /srv\n"},
]
# Which snapshot each 15-minute run sees: worse, worse, still bad, cleaned up.
RUNS = [0, 1, 2, 2, 0]
LEVELS = ["OK", "WARN", "CRIT"]


def level(value: float, warn: float, crit: float) -> int:
    return 2 if value >= crit else 1 if value >= warn else 0


def check_load(text: str) -> list[tuple[int, str]]:
    one = float(text.split()[0])
    per_cpu = one / CPUS
    return [(level(per_cpu, 1.0, 2.0), f"load      {per_cpu:.2f} per CPU (1m {one} / {CPUS} CPUs)")]


def check_memory(text: str) -> list[tuple[int, str]]:
    info = {k.strip(): int(v.split()[0]) for k, v in (line.split(":") for line in text.splitlines())}
    avail = info["MemAvailable"] / info["MemTotal"] * 100
    # low availability is bad, so compare the "used" share against the thresholds
    return [(level(100 - avail, 80, 90), f"memory    {avail:.0f}% available")]


def check_disks(text: str) -> list[tuple[int, str]]:
    results = []
    for line in text.splitlines()[1:]:
        *_, capacity, mount = line.split(maxsplit=5)
        pct = int(capacity.rstrip("%"))
        results.append((level(pct, 85, 95), f"disk {mount:<4} {pct}% used"))
    return results


def run_checks(snapshot: dict) -> tuple[int, list[tuple[int, str]]]:
    results = check_load(snapshot["loadavg"]) + check_memory(snapshot["meminfo"]) + check_disks(snapshot["df"])
    return max(lvl for lvl, _ in results), results


def write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def report_text(host: str, when: dt.datetime, status: int, results) -> str:
    lines = [f"system check {host} {when:%Y-%m-%d %H:%M}", f"status: {LEVELS[status]} (exit {status})"]
    lines += [f"  {LEVELS[lvl]:<5} {text}" for lvl, text in results]
    return "\n".join(lines) + "\n"


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def main() -> None:
    start = dt.datetime(2026, 3, 14, 6, 0)
    clock = FakeClock()
    scheduler = sched.scheduler(clock.time, clock.sleep)
    previous = {"status": None}
    snapshots = iter(SNAPSHOTS[i] for i in RUNS)

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)

        def check_once() -> None:
            when = start + dt.timedelta(seconds=clock.time())
            status, results = run_checks(next(snapshots))
            text = report_text("web-01", when, status, results)
            write_atomic(out_dir / f"report-{when:%Y%m%d-%H%M}.txt", text)
            write_atomic(out_dir / "latest.txt", text)
            old = previous["status"]
            if old != status:
                was = "start" if old is None else LEVELS[old]
                print(f"{when:%H:%M} notify: {was} -> {LEVELS[status]}")
            else:
                print(f"{when:%H:%M} unchanged ({LEVELS[status]}), no notification")
            previous["status"] = status

        for n in range(len(RUNS)):
            scheduler.enter(15 * 60 * n, 1, check_once)  # cron: */15 * * * *
        scheduler.run()

        print()
        print("files:", ", ".join(sorted(p.name for p in out_dir.iterdir())))
        print()
        print((out_dir / "report-20260314-0630.txt").read_text(encoding="utf-8"), end="")
        print()
        print((out_dir / "latest.txt").read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()

# Output:
# 06:00 notify: start -> OK
# 06:15 notify: OK -> WARN
# 06:30 notify: WARN -> CRIT
# 06:45 unchanged (CRIT), no notification
# 07:00 notify: CRIT -> OK
#
# files: latest.txt, report-20260314-0600.txt, report-20260314-0615.txt, report-20260314-0630.txt, report-20260314-0645.txt, report-20260314-0700.txt
#
# system check web-01 2026-03-14 06:30
# status: CRIT (exit 2)
#   CRIT  load      2.46 per CPU (1m 9.84 / 4 CPUs)
#   CRIT  memory    6% available
#   CRIT  disk /    96% used
#   OK    disk /srv 35% used
#
# system check web-01 2026-03-14 07:00
# status: OK (exit 0)
#   OK    load      0.10 per CPU (1m 0.42 / 4 CPUs)
#   OK    memory    61% available
#   OK    disk /    71% used
#   OK    disk /srv 34% used
