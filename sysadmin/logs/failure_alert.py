"""failure_alert v2 — timely "clear", cooldown, and success-after-failures

v1 counted failed logins per source in a sliding window. Running it for a
month showed three things to fix:

- "clear" arrived late, because a source's window was only re-checked when
  that source failed again. v2 advances time on every log line and computes
  the exact moment the window dropped below the threshold: the time the
  oldest of the last N failures expired.
- An attacker who pauses and comes back pages on-call again. v2 keeps a
  per-source cooldown (2 h here): a repeat burst inside it is logged as
  "repeat" with a lower severity instead of a new page.
- The event that matters most was not detected at all: a successful login
  from a source that was failing a moment ago. "Accepted ... from <ip>"
  while that ip has failures in its window is CRIT: possible compromise.

Events are still derived only from log timestamps, so replaying a file is
exact.
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
ACCEPTED = re.compile(
    r"^(?P<mon>\w{3}) +(?P<day>\d+) (?P<time>[\d:]{8}) \S+ sshd\[\d+\]: "
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.]+) ")


def stamp(m: re.Match) -> dt.datetime:
    hh, mm, ss = map(int, m["time"].split(":"))
    return dt.datetime(YEAR, MONTHS[m["mon"]], int(m["day"]), hh, mm, ss)


def events(lines):
    """Yield (time, kind, ip, user) for failed and accepted logins."""
    for line in lines:
        if m := FAILED.match(line):
            yield stamp(m), "failed", m["ip"], m["user"]
        elif m := ACCEPTED.match(line):
            yield stamp(m), "accepted", m["ip"], m["user"]


def failures(lines):
    for ts, kind, ip, user in events(lines):
        if kind == "failed":
            yield ts, ip, user


class Detector:
    def __init__(self, threshold=5, window=dt.timedelta(minutes=10), cooldown=dt.timedelta(hours=2)):
        self.threshold, self.window, self.cooldown = threshold, window, cooldown
        self.recent: dict[str, deque] = defaultdict(deque)
        self.alerting: set[str] = set()
        self.last_alert: dict[str, dt.datetime] = {}

    def _expire(self, now: dt.datetime):
        """Emit 'clear' for every alerting source whose window drained by `now`."""
        for ip in sorted(self.alerting):
            q = self.recent[ip]
            clear_at = q[-self.threshold] + self.window
            if clear_at <= now:
                self.alerting.discard(ip)
                yield clear_at, "info", ip, f"clear, under {self.threshold} failures per {self.window.seconds // 60} min"

    def feed(self, ts: dt.datetime, kind: str, ip: str, user: str):
        out = list(self._expire(ts))
        q = self.recent[ip]
        while q and ts - q[0] > self.window:
            q.popleft()
        if kind == "accepted":
            if q:
                out.append((ts, "CRIT", ip, f"login as {user} succeeded after {len(q)} failure(s) "
                                            f"in {self.window.seconds // 60} min: possible compromise"))
            return out
        q.append(ts)
        if len(q) >= self.threshold and ip not in self.alerting:
            self.alerting.add(ip)
            last = self.last_alert.get(ip)
            if last is not None and ts - last < self.cooldown:
                out.append((ts, "warn", ip, f"repeat burst, {len(q)} failures (within cooldown, no page)"))
            else:
                self.last_alert[ip] = ts
                out.append((ts, "PAGE", ip, f"{len(q)} failures in {(q[-1] - q[0]).seconds}s, last user {user}"))
        return out

    def finish(self, now: dt.datetime):
        return list(self._expire(now))


def detect(lines, **rules):
    det = Detector(**rules)
    last = None
    for ts, kind, ip, user in events(lines):
        yield from det.feed(ts, kind, ip, user)
        last = ts
    if last is not None:
        yield from det.finish(last + det.window)  # let open windows drain after the log ends


def main() -> None:
    lines = AUTH_LOG.splitlines()
    total = defaultdict(int)
    for _, ip, _ in failures(lines):
        total[ip] += 1
    print("failures per source:", ", ".join(f"{ip}={n}" for ip, n in sorted(total.items())))
    print()
    print("rule: 5 failures in 10 minutes, 2 h cooldown")
    for ts, level, ip, text in detect(lines):
        print(f"  {ts:%H:%M:%S} {level:<4} {ip:<13} {text}")
    print()
    print("rule: 5 failures in 10 minutes, 30 min cooldown")
    for ts, level, ip, text in detect(lines, cooldown=dt.timedelta(minutes=30)):
        if level in ("PAGE", "warn"):
            print(f"  {ts:%H:%M:%S} {level:<4} {ip:<13} {text}")


if __name__ == "__main__":
    main()

# Output:
# failures per source: 192.0.2.14=5, 198.51.100.7=6, 203.0.113.50=13
#
# rule: 5 failures in 10 minutes, 2 h cooldown
#   03:10:16 PAGE 203.0.113.50  5 failures in 14s, last user test
#   03:20:12 info 203.0.113.50  clear, under 5 failures per 10 min
#   04:09:55 PAGE 192.0.2.14    5 failures in 464s, last user admin
#   04:10:31 CRIT 192.0.2.14    login as admin succeeded after 5 failure(s) in 10 min: possible compromise
#   04:12:11 info 192.0.2.14    clear, under 5 failures per 10 min
#   04:31:15 warn 203.0.113.50  repeat burst, 5 failures (within cooldown, no page)
#   04:41:00 info 203.0.113.50  clear, under 5 failures per 10 min
#
# rule: 5 failures in 10 minutes, 30 min cooldown
#   03:10:16 PAGE 203.0.113.50  5 failures in 14s, last user test
#   04:09:55 PAGE 192.0.2.14    5 failures in 464s, last user admin
#   04:31:15 PAGE 203.0.113.50  5 failures in 15s, last user root
