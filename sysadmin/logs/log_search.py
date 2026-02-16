r"""log_search v4 — regular expressions and grep-style context lines

Keywords stop being enough the first time the question is "failed logins
from 203.0.113.0/24 for any user". v4 adds -e PATTERN (repeatable, Python
re syntax) next to -k, and context lines like grep's -B/-A/-C:

    log_search.py -e 'Failed password for (invalid user )?\w+ from 203\.0\.113\.' -B1 -A1 auth.log
    log_search.py --sample app -e 'ERROR|CRITICAL' -A3

Matching lines are printed as `N: line`, context lines as `N- line`, and a
`--` separates groups that are not adjacent, the same conventions as grep,
so the output reads the way people expect. Before-context is a bounded
deque, so memory stays constant however long the file is. Patterns are
compiled once, up front: a typo in a regex is a usage error (exit 2) before
any file is opened, not a traceback halfway through a 2 GB log. Context is
taken from the lines inside the --since/--until range.
"""

import argparse
import datetime as dt
import re
import shlex
import sys
from collections import deque
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
    parser.add_argument("-e", "--regex", dest="patterns", action="append", default=[],
                        help="regular expression to look for; repeat for several")
    parser.add_argument("--all", action="store_true", help="require every -k/-e (default: any)")
    parser.add_argument("-i", "--ignore-case", action="store_true")
    parser.add_argument("-c", "--count", action="store_true", help="print only match counts")
    parser.add_argument("-B", "--before", type=int, default=0, metavar="N", help="lines of context before")
    parser.add_argument("-A", "--after", type=int, default=0, metavar="N", help="lines of context after")
    parser.add_argument("-C", "--context", type=int, metavar="N", help="same as -B N -A N")
    parser.add_argument("--since", type=cli_time, help="keep lines at or after this time")
    parser.add_argument("--until", type=cli_time, help="keep lines before this time")
    parser.add_argument("--year", type=int, default=dt.date.today().year,
                        help="year for syslog timestamps, which have none (default: this year)")
    parser.add_argument("--sample", nargs="?", const="auth", choices=sorted(SAMPLES),
                        help="search an embedded sample log (default: auth)")
    return parser


def matcher(keywords: list[str], patterns: list[re.Pattern], require_all: bool, ignore_case: bool):
    fold = str.casefold if ignore_case else (lambda s: s)
    needles = [fold(k) for k in keywords]
    combine = all if require_all else any

    def match(line: str) -> bool:
        if not needles and not patterns:
            return True
        haystack = fold(line)
        tests = [n in haystack for n in needles] + [p.search(line) is not None for p in patterns]
        return combine(tests)

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


def search(lines, match, year, since=None, until=None, before=0, after=0) -> Iterator[tuple[str, int, str]]:
    """Yield (kind, number, line): kind ':' is a match, '-' context, '--' a group break."""
    window: deque[tuple[int, str]] = deque(maxlen=before)
    after_left = 0
    last_printed = 0
    for number, line, ts in timed(lines, year):
        if not in_range(ts, since, until):
            continue
        if match(line):
            out = [("-", n, text) for n, text in window] + [(":", number, line)]
            window.clear()
            after_left = after
        elif after_left:
            out = [("-", number, line)]
            after_left -= 1
        else:
            window.append((number, line))
            continue
        for kind, n, text in out:
            if last_printed and n > last_printed + 1:
                yield "--", 0, ""
            yield kind, n, text
            last_printed = n


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
    if not (args.keywords or args.patterns) and args.since is None and args.until is None:
        parser.error("give at least one -k/-e or a --since/--until range")
    if args.context is not None:
        args.before = args.after = args.context
    flags = re.IGNORECASE if args.ignore_case else 0
    try:
        patterns = [re.compile(p, flags) for p in args.patterns]
    except re.error as exc:
        parser.error(f"bad regex {exc.pattern!r}: {exc.msg} at position {exc.pos}")
    if not args.files and not args.sample:
        args.files = ["-"]
    match = matcher(args.keywords, patterns, args.all, args.ignore_case)
    multi = len(args.files) + bool(args.sample) > 1
    total = 0
    for name, lines in sources(args):
        count = 0
        for kind, number, line in search(lines, match, args.year, args.since, args.until,
                                         args.before, args.after):
            count += kind == ":"
            if args.count:
                continue
            if kind == "--":
                print("--")
            else:
                prefix = f"{name}:" if multi else ""
                print(f"{prefix}{number}{kind} {line}")
        if args.count:
            print(f"{name}: {count}")
        total += count
    return 0 if total else 1


def demo(argv: list[str]) -> None:
    print("$ " + shlex.join(["log_search.py", *argv]))
    try:
        status = run(argv)
    except SystemExit as exc:  # argparse reports usage errors on stderr
        status = exc.code
    print(f"[exit {status}]")


def main() -> None:
    if len(sys.argv) > 1:
        sys.exit(run(sys.argv[1:]))
    demo(["--sample", "-e", r"Failed password for (invalid user )?\w+ from 203\.0\.113\.", "-B1", "-A1"])
    demo(["--sample", "-e", r"session (opened|closed) for user root", "-C1"])
    demo(["--sample", "app", "-e", "ERROR|CRITICAL", "-A3"])
    demo(["--sample", "--all", "-k", "sshd", "-e", r"port 6\d{4}\b", "-c"])
    demo(["--sample", "-e", "Failed (password"])


if __name__ == "__main__":
    main()

# Output:
# $ log_search.py --sample -e 'Failed password for (invalid user )?\w+ from 203\.0\.113\.' -B1 -A1
# 5- Mar 14 09:31:07 bastion sshd[3188]: Invalid user admin from 203.0.113.50 port 40112
# 6: Mar 14 09:31:09 bastion sshd[3188]: Failed password for invalid user admin from 203.0.113.50 port 40112 ssh2
# 7: Mar 14 09:31:14 bastion sshd[3190]: Failed password for root from 203.0.113.50 port 40118 ssh2
# 8: Mar 14 09:31:20 bastion sshd[3190]: Failed password for root from 203.0.113.50 port 40118 ssh2
# 9- Mar 14 09:31:20 bastion sshd[3190]: error: maximum authentication attempts exceeded for root from 203.0.113.50 port 40118 ssh2 [preauth]
# [exit 0]
# $ log_search.py --sample -e 'session (opened|closed) for user root' -C1
# 1: Mar 14 09:12:01 bastion CRON[2211]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
# 2: Mar 14 09:12:01 bastion CRON[2211]: pam_unix(cron:session): session closed for user root
# 3- Mar 14 09:26:41 bastion sshd[3120]: Accepted publickey for deploy from 10.0.4.21 port 51022 ssh2: ED25519 SHA256:q1w2e3
# --
# 10- Mar 14 09:44:52 bastion sudo:   deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart app
# 11: Mar 14 09:44:52 bastion sudo: pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1001)
# 12- Mar 14 10:02:13 bastion sshd[3301]: Failed password for deploy from 198.51.100.7 port 60231 ssh2
# [exit 0]
# $ log_search.py --sample app -e 'ERROR|CRITICAL' -A3
# 2: 2026-03-14T10:14:59.902114+00:00 bastion app[2875]: ERROR report export failed
# 3- Traceback (most recent call last):
# 4-   File "/srv/app/export.py", line 88, in build
# 5- MemoryError
# [exit 0]
# $ log_search.py --sample --all -k sshd -e 'port 6\d{4}\b' -c
# auth: 2
# [exit 0]
# $ log_search.py --sample -e 'Failed (password'
# [exit 2]
