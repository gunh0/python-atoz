"""log_search v3 — --since/--until time ranges over syslog and ISO timestamps

"What happened between 09:30 and 10:05?" is the first question in every
incident review, and grep cannot answer it. v3 parses the timestamp at the
start of each line and filters on a half-open range [since, until):

    log_search.py --year 2026 --since "2026-03-14 09:30" --until "2026-03-14 10:05" -k sshd auth.log

Two timestamp formats are understood: classic BSD syslog ("Mar 14 09:31:07",
no year, hence --year, default the current year) and RFC 3339 as written by
rsyslog's high-precision template or `journalctl -o short-iso`. Month names
are mapped by hand instead of strptime("%b"), which depends on the locale.
ISO offsets are dropped and times compared as wall clock, which is right as
long as one host logs in one zone.

Lines without a timestamp (stack traces, wrapped messages) inherit the time
of the line before them, so a range filter keeps a traceback together with
the error that started it. -k is now optional: a time range alone is a valid
query.
"""

import argparse
import datetime as dt
import re
import sys
from collections.abc import Iterable, Iterator

AUTH_LOG = """\
Mar 14 09:12:01 bastion CRON[2211]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Mar 14 09:12:01 bastion CRON[2211]: pam_unix(cron:session): session closed for user root
Mar 14 09:26:41 bastion sshd[3120]: Accepted publickey for deploy from 10.0.4.21 port 51022 ssh2: ED25519 SHA256:q1w2e3
Mar 14 09:26:41 bastion sshd[3120]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)
Mar 14 09:31:07 bastion sshd[3188]: Invalid user admin from 203.0.113.50 port 40112
Mar 14 09:31:09 bastion sshd[3188]: Failed password for invalid user admin from 203.0.113.50 port 40112 ssh2
Mar 14 09:31:14 bastion sshd[3190]: Failed password for root from 203.0.113.50 port 40118 ssh2
Mar 14 09:31:20 bastion sshd[3190]: Failed password for root from 203.0.113.50 port 40118 ssh2
Mar 14 09:31:20 bastion sshd[3190]: error: maximum authentication attempts exceeded for root from 203.0.113.50 port 40118 ssh2 [preauth]
Mar 14 09:44:52 bastion sudo:   deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart app
Mar 14 09:44:52 bastion sudo: pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1001)
Mar 14 10:02:13 bastion sshd[3301]: Failed password for deploy from 198.51.100.7 port 60231 ssh2
Mar 14 10:02:19 bastion sshd[3301]: Accepted password for deploy from 198.51.100.7 port 60231 ssh2
Mar 14 10:15:00 bastion kernel: [81234.551201] Out of memory: Killed process 2875 (java) total-vm:8123412kB
Mar 14 10:15:02 bastion systemd[1]: app.service: Main process exited, code=killed, status=9/KILL
Mar 14 10:15:12 bastion systemd[1]: app.service: Scheduled restart job, restart counter is at 1.
Mar 14 11:40:33 bastion sshd[3120]: pam_unix(sshd:session): session closed for user deploy
"""

APP_LOG = """\
2026-03-14T10:14:58.120331+00:00 bastion app[2875]: GET /api/report 200 1840ms
2026-03-14T10:14:59.902114+00:00 bastion app[2875]: ERROR report export failed
Traceback (most recent call last):
  File "/srv/app/export.py", line 88, in build
MemoryError
2026-03-14T10:15:12.004120+00:00 bastion app[3410]: started, pid 3410
2026-03-14T10:16:40.551200+00:00 bastion app[3410]: GET /healthz 200 3ms
"""

SAMPLES = {"auth": AUTH_LOG, "app": APP_LOG}
MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}
SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) ")
ISO_TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)? ")


def parse_time(line: str, year: int) -> dt.datetime | None:
    if m := SYSLOG_TS.match(line):
        mon, day, hh, mm, ss = m.groups()
        if mon in MONTHS:
            return dt.datetime(year, MONTHS[mon], int(day), int(hh), int(mm), int(ss))
    if m := ISO_TS.match(line):
        return dt.datetime.fromisoformat(m.group(1))
    return None


def cli_time(text: str) -> dt.datetime:
    try:
        return dt.datetime.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an ISO date/time: {text!r}") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="log_search.py", description="Search log files.")
    parser.add_argument("files", nargs="*", help="log files to read ('-' for stdin)")
    parser.add_argument("-k", "--keyword", dest="keywords", action="append", default=[],
                        help="keyword to look for; repeat for several")
    parser.add_argument("--all", action="store_true", help="require every keyword (default: any)")
    parser.add_argument("-i", "--ignore-case", action="store_true")
    parser.add_argument("-c", "--count", action="store_true", help="print only match counts")
    parser.add_argument("--since", type=cli_time, help="keep lines at or after this time")
    parser.add_argument("--until", type=cli_time, help="keep lines before this time")
    parser.add_argument("--year", type=int, default=dt.date.today().year,
                        help="year for syslog timestamps, which have none (default: this year)")
    parser.add_argument("--sample", nargs="?", const="auth", choices=sorted(SAMPLES),
                        help="search an embedded sample log (default: auth)")
    return parser


def matcher(keywords: list[str], require_all: bool, ignore_case: bool):
    fold = str.casefold if ignore_case else (lambda s: s)
    needles = [fold(k) for k in keywords]
    combine = all if require_all else any

    def match(line: str) -> bool:
        if not needles:
            return True
        haystack = fold(line)
        return combine(n in haystack for n in needles)

    return match


def timed(lines: Iterable[str], year: int) -> Iterator[tuple[int, str, dt.datetime | None]]:
    """Yield (number, line, timestamp); untimed lines inherit the previous time."""
    last = None
    for number, line in enumerate(lines, start=1):
        line = line.rstrip("\n")
        last = parse_time(line, year) or last
        yield number, line, last


def in_range(ts: dt.datetime | None, since, until) -> bool:
    if ts is None:
        return since is None and until is None
    return (since is None or ts >= since) and (until is None or ts < until)


def search(lines, match, year, since=None, until=None) -> Iterator[tuple[int, str]]:
    for number, line, ts in timed(lines, year):
        if in_range(ts, since, until) and match(line):
            yield number, line


def sources(args) -> Iterator[tuple[str, Iterable[str]]]:
    if args.sample:
        yield args.sample, SAMPLES[args.sample].splitlines()
    for name in args.files:
        if name == "-":
            yield "(stdin)", sys.stdin
        else:
            with open(name, encoding="utf-8", errors="replace") as fh:
                yield name, fh


def run(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.keywords and args.since is None and args.until is None:
        parser.error("give at least one -k or a --since/--until range")
    if not args.files and not args.sample:
        args.files = ["-"]
    match = matcher(args.keywords, args.all, args.ignore_case)
    multi = len(args.files) + bool(args.sample) > 1
    total = 0
    for name, lines in sources(args):
        count = 0
        for number, line in search(lines, match, args.year, args.since, args.until):
            count += 1
            if not args.count:
                prefix = f"{name}:" if multi else ""
                print(f"{prefix}{number}: {line}")
        if args.count:
            print(f"{name}: {count}")
        total += count
    return 0 if total else 1


def demo(argv: list[str]) -> None:
    print("$ log_search.py " + " ".join(f"'{a}'" if " " in a else a for a in argv))
    try:
        status = run(argv)
    except SystemExit as exc:  # argparse reports usage errors on stderr
        status = exc.code
    print(f"[exit {status}]")


def main() -> None:
    if len(sys.argv) > 1:
        sys.exit(run(sys.argv[1:]))
    demo(["--sample", "--year", "2026", "--since", "2026-03-14 09:30", "--until", "2026-03-14 10:05",
          "-k", "sshd"])
    demo(["--sample", "app", "--since", "2026-03-14 10:15", "--until", "2026-03-14 10:16"])
    demo(["--sample", "app", "--since", "2026-03-14 10:14:59", "--until", "2026-03-14 10:15"])
    demo(["--sample", "--year", "2026", "-c", "--since", "2026-03-14 11:00", "-k", "session"])
    demo(["--sample", "--since", "yesterday"])


if __name__ == "__main__":
    main()

# Output:
# $ log_search.py --sample --year 2026 --since '2026-03-14 09:30' --until '2026-03-14 10:05' -k sshd
# 5: Mar 14 09:31:07 bastion sshd[3188]: Invalid user admin from 203.0.113.50 port 40112
# 6: Mar 14 09:31:09 bastion sshd[3188]: Failed password for invalid user admin from 203.0.113.50 port 40112 ssh2
# 7: Mar 14 09:31:14 bastion sshd[3190]: Failed password for root from 203.0.113.50 port 40118 ssh2
# 8: Mar 14 09:31:20 bastion sshd[3190]: Failed password for root from 203.0.113.50 port 40118 ssh2
# 9: Mar 14 09:31:20 bastion sshd[3190]: error: maximum authentication attempts exceeded for root from 203.0.113.50 port 40118 ssh2 [preauth]
# 12: Mar 14 10:02:13 bastion sshd[3301]: Failed password for deploy from 198.51.100.7 port 60231 ssh2
# 13: Mar 14 10:02:19 bastion sshd[3301]: Accepted password for deploy from 198.51.100.7 port 60231 ssh2
# [exit 0]
# $ log_search.py --sample app --since '2026-03-14 10:15' --until '2026-03-14 10:16'
# 6: 2026-03-14T10:15:12.004120+00:00 bastion app[3410]: started, pid 3410
# [exit 0]
# $ log_search.py --sample app --since '2026-03-14 10:14:59' --until '2026-03-14 10:15'
# 2: 2026-03-14T10:14:59.902114+00:00 bastion app[2875]: ERROR report export failed
# 3: Traceback (most recent call last):
# 4:   File "/srv/app/export.py", line 88, in build
# 5: MemoryError
# [exit 0]
# $ log_search.py --sample --year 2026 -c --since '2026-03-14 11:00' -k session
# auth: 1
# [exit 0]
# $ log_search.py --sample --since yesterday
# [exit 2]
