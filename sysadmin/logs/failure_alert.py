"""failure_alert v1 — alert on N failed logins from one source within M minutes

A single "Failed password" line is noise; the internet does that to every
SSH server all day. Five from one address in ten minutes is a brute-force
attempt worth an alert (and the rule fail2ban implements). Counting per
day or per file gets it wrong in both directions, so the rule here is a
sliding window: for each source keep the timestamps of its recent
failures in a deque, drop the ones older than M minutes, alert when N
remain.

Timestamps come from the log lines, not the clock, so the same file gives
the same alerts whether it is processed live or replayed a week later.
v1 alerts once when a source crosses the threshold and stays quiet until
its window drains below it again, so a 200-attempt burst is one alert,
not 196. Known gap: the window is only re-checked when the same source
fails again, so "clear" shows up late (see 203.0.113.50 below).
"""

import datetime as dt
import re
from collections import defaultdict, deque

AUTH_LOG = """\
Mar 14 03:10:02 bastion sshd[5101]: Failed password for root from 203.0.113.50 port 50211 ssh2
Mar 14 03:10:05 bastion sshd[5101]: Failed password for root from 203.0.113.50 port 50211 ssh2
Mar 14 03:10:09 bastion sshd[5103]: Failed password for invalid user oracle from 203.0.113.50 port 50240 ssh2
Mar 14 03:10:12 bastion sshd[5103]: Failed password for invalid user oracle from 203.0.113.50 port 50240 ssh2
Mar 14 03:10:16 bastion sshd[5105]: Failed password for invalid user test from 203.0.113.50 port 50266 ssh2
Mar 14 03:10:19 bastion sshd[5105]: Failed password for invalid user test from 203.0.113.50 port 50266 ssh2
Mar 14 03:10:23 bastion sshd[5107]: Failed password for root from 203.0.113.50 port 50290 ssh2
Mar 14 03:10:27 bastion sshd[5107]: Failed password for root from 203.0.113.50 port 50290 ssh2
Mar 14 03:12:40 bastion sshd[5120]: Failed password for deploy from 198.51.100.7 port 41001 ssh2
Mar 14 03:21:02 bastion sshd[5133]: Failed password for deploy from 198.51.100.7 port 41077 ssh2
Mar 14 03:29:44 bastion sshd[5150]: Failed password for deploy from 198.51.100.7 port 41123 ssh2
Mar 14 03:38:15 bastion sshd[5162]: Failed password for deploy from 198.51.100.7 port 41190 ssh2
Mar 14 03:41:30 bastion sshd[5170]: Accepted publickey for deploy from 10.0.4.21 port 51022 ssh2
Mar 14 03:46:51 bastion sshd[5181]: Failed password for deploy from 198.51.100.7 port 41255 ssh2
Mar 14 03:55:20 bastion sshd[5199]: Failed password for deploy from 198.51.100.7 port 41302 ssh2
Mar 14 04:02:11 bastion sshd[5210]: Failed password for admin from 192.0.2.14 port 33010 ssh2
Mar 14 04:03:40 bastion sshd[5210]: Failed password for admin from 192.0.2.14 port 33010 ssh2
Mar 14 04:05:02 bastion sshd[5214]: Failed password for admin from 192.0.2.14 port 33044 ssh2
Mar 14 04:07:30 bastion sshd[5214]: Failed password for admin from 192.0.2.14 port 33044 ssh2
Mar 14 04:09:55 bastion sshd[5219]: Failed password for admin from 192.0.2.14 port 33090 ssh2
Mar 14 04:10:31 bastion sshd[5219]: Accepted password for admin from 192.0.2.14 port 33090 ssh2
Mar 14 04:31:00 bastion sshd[5240]: Failed password for root from 203.0.113.50 port 51800 ssh2
Mar 14 04:31:04 bastion sshd[5240]: Failed password for root from 203.0.113.50 port 51800 ssh2
Mar 14 04:31:07 bastion sshd[5242]: Failed password for root from 203.0.113.50 port 51822 ssh2
Mar 14 04:31:11 bastion sshd[5242]: Failed password for root from 203.0.113.50 port 51822 ssh2
Mar 14 04:31:15 bastion sshd[5244]: Failed password for root from 203.0.113.50 port 51840 ssh2
"""

YEAR = 2026  # syslog lines carry no year
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
FAILED = re.compile(
    r"^(?P<mon>\w{3}) +(?P<day>\d+) (?P<time>[\d:]{8}) \S+ sshd\[\d+\]: "
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) ")


def failures(lines):
    for line in lines:
        if m := FAILED.match(line):
            hh, mm, ss = map(int, m["time"].split(":"))
            ts = dt.datetime(YEAR, MONTHS[m["mon"]], int(m["day"]), hh, mm, ss)
            yield ts, m["ip"], m["user"]


def detect(lines, threshold: int = 5, window: dt.timedelta = dt.timedelta(minutes=10)):
    recent: dict[str, deque] = defaultdict(deque)
    alerting: set[str] = set()
    for ts, ip, user in failures(lines):
        q = recent[ip]
        q.append(ts)
        while q and ts - q[0] > window:
            q.popleft()
        if len(q) >= threshold and ip not in alerting:
            alerting.add(ip)
            span = (q[-1] - q[0]).total_seconds()
            yield f"{ts:%H:%M:%S} ALERT {ip}: {len(q)} failures in {span:.0f}s (last user {user})"
        elif len(q) < threshold and ip in alerting:
            alerting.discard(ip)
            yield f"{ts:%H:%M:%S} clear {ip}: back under {threshold} in {window.seconds // 60} min"


def main() -> None:
    lines = AUTH_LOG.splitlines()
    total = defaultdict(int)
    for _, ip, _ in failures(lines):
        total[ip] += 1
    print("failures per source:", ", ".join(f"{ip}={n}" for ip, n in sorted(total.items())))
    print()
    print("rule: 5 failures in 10 minutes")
    for event in detect(lines):
        print(" ", event)
    print()
    print("rule: 3 failures in 20 minutes (catches the slow one too)")
    for event in detect(lines, threshold=3, window=dt.timedelta(minutes=20)):
        print(" ", event)


if __name__ == "__main__":
    main()

# Output:
# failures per source: 192.0.2.14=5, 198.51.100.7=6, 203.0.113.50=13
#
# rule: 5 failures in 10 minutes
#   03:10:16 ALERT 203.0.113.50: 5 failures in 14s (last user test)
#   04:09:55 ALERT 192.0.2.14: 5 failures in 464s (last user admin)
#   04:31:00 clear 203.0.113.50: back under 5 in 10 min
#   04:31:15 ALERT 203.0.113.50: 5 failures in 15s (last user root)
#
# rule: 3 failures in 20 minutes (catches the slow one too)
#   03:10:09 ALERT 203.0.113.50: 3 failures in 7s (last user oracle)
#   03:29:44 ALERT 198.51.100.7: 3 failures in 1024s (last user deploy)
#   04:05:02 ALERT 192.0.2.14: 3 failures in 171s (last user admin)
#   04:31:00 clear 203.0.113.50: back under 3 in 20 min
#   04:31:07 ALERT 203.0.113.50: 3 failures in 7s (last user root)
