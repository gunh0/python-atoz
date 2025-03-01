"""log_search v1 — keyword filter over auth.log / syslog lines

The first version of a tool every admin ends up writing: "show me the lines
that mention X", the part of grep you use 90% of the time, but in Python so
it can grow into something grep cannot do (time ranges, per-host summaries,
alerting). v1 keeps it deliberately small: one keyword, optional
case-insensitive match, and iteration over lines so a 2 GB log never has to
fit in memory. It works on any iterable of lines, so an open file, a gzip
stream or the embedded sample all go through the same function.

Each match is printed with its 1-based line number, which is what you need
when you open the file in an editor afterwards.
"""

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


def search(lines: Iterable[str], keyword: str, ignore_case: bool = False) -> Iterator[tuple[int, str]]:
    """Yield (line_number, line) for every line containing keyword."""
    needle = keyword.casefold() if ignore_case else keyword
    for number, line in enumerate(lines, start=1):
        line = line.rstrip("\n")
        haystack = line.casefold() if ignore_case else line
        if needle in haystack:
            yield number, line


def show(lines: Iterable[str], keyword: str, ignore_case: bool = False) -> None:
    flag = " (ignore case)" if ignore_case else ""
    print(f"== {keyword!r}{flag}")
    count = 0
    for number, line in search(lines, keyword, ignore_case):
        print(f"{number:>3}: {line}")
        count += 1
    print(f"-- {count} match(es)")


def main() -> None:
    lines = AUTH_LOG.splitlines(keepends=True)
    show(lines, "Failed password")
    show(lines, "out of memory", ignore_case=True)
    show(lines, "segfault")


if __name__ == "__main__":
    main()

# Output:
# == 'Failed password'
#   6: Mar 14 09:31:09 bastion sshd[3188]: Failed password for invalid user admin from 203.0.113.50 port 40112 ssh2
#   7: Mar 14 09:31:14 bastion sshd[3190]: Failed password for root from 203.0.113.50 port 40118 ssh2
#   8: Mar 14 09:31:20 bastion sshd[3190]: Failed password for root from 203.0.113.50 port 40118 ssh2
#  12: Mar 14 10:02:13 bastion sshd[3301]: Failed password for deploy from 198.51.100.7 port 60231 ssh2
# -- 4 match(es)
# == 'out of memory' (ignore case)
#  14: Mar 14 10:15:00 bastion kernel: [81234.551201] Out of memory: Killed process 2875 (java) total-vm:8123412kB
# -- 1 match(es)
# == 'segfault'
# -- 0 match(es)
