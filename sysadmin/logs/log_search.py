"""log_search v2 — argparse front end, several keywords, grep-style exit codes

v1 was a function you edited before each run. v2 turns it into a command:

    log_search.py -k "Failed password" -k "Invalid user" /var/log/auth.log
    log_search.py --all -k sshd -k root --count auth.log auth.log.1

Repeating -k collects keywords into a list (action="append"); by default a
line matches if it has any of them, --all requires every one. Several files
are allowed and, as in grep, matches are prefixed with the file name once
there is more than one. The exit status follows grep too: 0 when something
matched, 1 when nothing did, 2 for usage errors (argparse already exits 2),
so the tool composes in shell: `log_search.py ... && page_oncall`.

--sample searches the embedded log so the examples below run anywhere;
running the file without arguments executes those examples.
"""

import argparse
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

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="log_search.py", description="Search log files for keywords.")
    parser.add_argument("files", nargs="*", help="log files to read ('-' for stdin)")
    parser.add_argument("-k", "--keyword", dest="keywords", action="append", required=True,
                        help="keyword to look for; repeat for several")
    parser.add_argument("--all", action="store_true", help="require every keyword (default: any)")
    parser.add_argument("-i", "--ignore-case", action="store_true")
    parser.add_argument("-c", "--count", action="store_true", help="print only match counts")
    parser.add_argument("--sample", action="store_true", help="search the embedded sample log")
    return parser


def matcher(keywords: list[str], require_all: bool, ignore_case: bool):
    fold = str.casefold if ignore_case else (lambda s: s)
    needles = [fold(k) for k in keywords]
    combine = all if require_all else any

    def match(line: str) -> bool:
        haystack = fold(line)
        return combine(n in haystack for n in needles)

    return match


def search(lines: Iterable[str], match) -> Iterator[tuple[int, str]]:
    for number, line in enumerate(lines, start=1):
        line = line.rstrip("\n")
        if match(line):
            yield number, line


def sources(args) -> Iterator[tuple[str, Iterable[str]]]:
    if args.sample:
        yield "sample", AUTH_LOG.splitlines()
    for name in args.files:
        if name == "-":
            yield "(stdin)", sys.stdin
        else:
            with open(name, encoding="utf-8", errors="replace") as fh:
                yield name, fh


def run(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    if not args.files and not args.sample:
        args.files = ["-"]
    match = matcher(args.keywords, args.all, args.ignore_case)
    multi = len(args.files) + args.sample > 1
    total = 0
    for name, lines in sources(args):
        count = 0
        for number, line in search(lines, match):
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
    demo(["--sample", "-k", "Invalid user", "-k", "maximum authentication"])
    demo(["--sample", "--all", "-k", "Accepted", "-k", "deploy"])
    demo(["--sample", "-c", "-i", "-k", "SESSION OPENED"])
    demo(["--sample", "-k", "segfault"])
    demo(["--sample"])


if __name__ == "__main__":
    main()

# Output:
# $ log_search.py --sample -k 'Invalid user' -k 'maximum authentication'
# 5: Mar 14 09:31:07 bastion sshd[3188]: Invalid user admin from 203.0.113.50 port 40112
# 9: Mar 14 09:31:20 bastion sshd[3190]: error: maximum authentication attempts exceeded for root from 203.0.113.50 port 40118 ssh2 [preauth]
# [exit 0]
# $ log_search.py --sample --all -k Accepted -k deploy
# 3: Mar 14 09:26:41 bastion sshd[3120]: Accepted publickey for deploy from 10.0.4.21 port 51022 ssh2: ED25519 SHA256:q1w2e3
# 13: Mar 14 10:02:19 bastion sshd[3301]: Accepted password for deploy from 198.51.100.7 port 60231 ssh2
# [exit 0]
# $ log_search.py --sample -c -i -k 'SESSION OPENED'
# sample: 3
# [exit 0]
# $ log_search.py --sample -k segfault
# [exit 1]
# $ log_search.py --sample
# [exit 2]
