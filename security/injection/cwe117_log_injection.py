"""CWE-117: log injection — user input can forge log lines

https://cwe.mitre.org/data/definitions/117.html

Logging a username, a User-Agent or a URL path verbatim lets the client put a
newline in it, and everything after the newline looks like a new record
written by your application: a fake "login succeeded for admin" to mislead
the incident responder, or a line crafted to trip a log-based alert or
fail2ban rule. ANSI escape sequences go further on a terminal: they can hide
text or rewrite what `tail -f` shows.

Neutralise at the logging layer so no call site can forget: a Formatter
that escapes CR, LF and other control characters in the *message* (after %
args are merged; tracebacks stay readable), or structured logging where each
field is JSON-encoded. Prefer logging's own %s/args style over f-strings so
the formatter sees the final text in one place.
"""

import io
import json
import logging

FORGED = "mallory\nINFO auth login succeeded for user=admin from 10.0.0.1"
ANSI = "mallory\x1b[1A\x1b[2K\rINFO auth login succeeded for user=mallory"


class EscapingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        safe = "".join(c if c.isprintable() else repr(c)[1:-1] for c in msg)
        record = logging.makeLogRecord({**record.__dict__, "msg": safe, "args": None})
        return super().format(record)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({"level": record.levelname, "logger": record.name,
                           "msg": record.msg, "user": getattr(record, "user", None)})


def make_logger(name: str, formatter: logging.Formatter) -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.handlers[:] = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    return logger, stream


def show(title: str, stream: io.StringIO) -> None:
    print(title)
    for line in stream.getvalue().rstrip("\n").split("\n"):   # one entry per line in the file
        if "\x1b" in line or "\r" in line:
            print(f"  | {line!r}   <- a terminal shows only the part after \\r")
        else:
            print(f"  | {line}")


def main() -> None:
    plain = logging.Formatter("%(levelname)s %(name)s %(message)s")

    log, out = make_logger("auth", plain)
    for user in ("alice", FORGED, ANSI):
        log.warning(f"login failed for user={user}")
    show("noncompliant (f-string, plain formatter):", out)

    log, out = make_logger("auth", EscapingFormatter("%(levelname)s %(name)s %(message)s"))
    for user in ("alice", FORGED, ANSI):
        log.warning("login failed for user=%s", user)
    show("compliant (EscapingFormatter):", out)

    log, out = make_logger("auth", JsonFormatter())
    for user in ("alice", FORGED):
        log.warning("login failed", extra={"user": user})
    show("compliant (JSON fields):", out)


if __name__ == "__main__":
    main()

# Output:
# noncompliant (f-string, plain formatter):
#   | WARNING auth login failed for user=alice
#   | WARNING auth login failed for user=mallory
#   | INFO auth login succeeded for user=admin from 10.0.0.1
#   | 'WARNING auth login failed for user=mallory\x1b[1A\x1b[2K\rINFO auth login succeeded for user=mallory'   <- a terminal shows only the part after \r
# compliant (EscapingFormatter):
#   | WARNING auth login failed for user=alice
#   | WARNING auth login failed for user=mallory\nINFO auth login succeeded for user=admin from 10.0.0.1
#   | WARNING auth login failed for user=mallory\x1b[1A\x1b[2K\rINFO auth login succeeded for user=mallory
# compliant (JSON fields):
#   | {"level": "WARNING", "logger": "auth", "msg": "login failed", "user": "alice"}
#   | {"level": "WARNING", "logger": "auth", "msg": "login failed", "user": "mallory\nINFO auth login succeeded for user=admin from 10.0.0.1"}
