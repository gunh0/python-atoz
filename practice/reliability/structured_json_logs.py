"""Structured JSON logs — one event per line, fields instead of f-strings

https://cwe.mitre.org/data/definitions/117.html

A common idiom is logging with f-strings: `log.info(f"login ok user={user} ip={ip}")`.
It reads well in a terminal and is miserable everywhere else: the log
pipeline has to regex the message back apart, and when `user` contains a
newline an attacker can write a fake second line into your audit log (CWE-117,
log injection).

Emit one JSON object per line instead. Values go in as separate fields via
`extra=`, json.dumps escapes control characters, and the consumer parses with
json.loads — no regex. Keep exceptions as type and message fields (the full
traceback can go in its own field). The fixed-time filter below only exists to
make this demo's output stable; a real deployment keeps record.created.
"""

import io
import json
import logging
from collections import Counter
from datetime import datetime, timezone

RESERVED = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="seconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Anything passed through extra= becomes a top-level field.
        event.update({k: v for k, v in vars(record).items() if k not in RESERVED})
        if record.exc_info and record.exc_info[1] is not None:
            exc = record.exc_info[1]
            event["exc_type"] = type(exc).__name__
            event["exc_msg"] = str(exc)
        return json.dumps(event, sort_keys=True, default=str)


class FixedTime(logging.Filter):
    """Demo only: pin the timestamp so the output is reproducible."""

    def __init__(self, epoch: float) -> None:
        super().__init__()
        self.epoch = epoch

    def filter(self, record: logging.LogRecord) -> bool:
        record.created = self.epoch
        return True


def make_logger(name: str, formatter: logging.Formatter, stream: io.StringIO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.handlers.clear()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    handler.addFilter(FixedTime(1767225600.0))  # 2026-01-01T00:00:00Z
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


LOGINS = [("alice", "10.0.0.5"), ("bob\nINFO login ok user=admin ip=10.0.0.1", "203.0.113.9")]


def main() -> None:
    stream = io.StringIO()
    log = make_logger("plain", logging.Formatter("%(levelname)s %(message)s"), stream)
    for user, ip in LOGINS:
        log.info(f"login ok user={user} ip={ip}")
    lines = stream.getvalue().splitlines()
    print(f"noncompliant: {len(LOGINS)} events became {len(lines)} lines:")
    for line in lines:
        print(f"  {line}")
    forged = sum("user=admin" in line for line in lines)
    print(f"noncompliant: grep 'user=admin' finds {forged} login that never happened")
    print()

    stream = io.StringIO()
    log = make_logger("audit", JsonFormatter(), stream)
    for user, ip in LOGINS:
        log.info("login ok", extra={"user": user, "src_ip": ip, "event": "auth.login"})
    try:
        int("12a")
    except ValueError:
        log.exception("bad quota value", extra={"event": "quota.parse"})
    lines = stream.getvalue().splitlines()
    print(f"compliant:    {len(LOGINS) + 1} events, {len(lines)} lines:")
    for line in lines:
        print(f"  {line}")
    events = [json.loads(line) for line in lines]
    print(f"compliant:    users seen {[e.get('user') for e in events if e['event'] == 'auth.login']!r}")
    print(f"compliant:    by level {dict(Counter(e['level'] for e in events))}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: 2 events became 3 lines:
#   INFO login ok user=alice ip=10.0.0.5
#   INFO login ok user=bob
#   INFO login ok user=admin ip=10.0.0.1 ip=203.0.113.9
# noncompliant: grep 'user=admin' finds 1 login that never happened
#
# compliant:    3 events, 3 lines:
#   {"event": "auth.login", "level": "INFO", "logger": "audit", "msg": "login ok", "src_ip": "10.0.0.5", "ts": "2026-01-01T00:00:00+00:00", "user": "alice"}
#   {"event": "auth.login", "level": "INFO", "logger": "audit", "msg": "login ok", "src_ip": "203.0.113.9", "ts": "2026-01-01T00:00:00+00:00", "user": "bob\nINFO login ok user=admin ip=10.0.0.1"}
#   {"event": "quota.parse", "exc_msg": "invalid literal for int() with base 10: '12a'", "exc_type": "ValueError", "level": "ERROR", "logger": "audit", "msg": "bad quota value", "ts": "2026-01-01T00:00:00+00:00"}
# compliant:    users seen ['alice', 'bob\nINFO login ok user=admin ip=10.0.0.1']
# compliant:    by level {'INFO': 2, 'ERROR': 1}
