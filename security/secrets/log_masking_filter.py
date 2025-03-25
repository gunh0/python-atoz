"""CWE-532: secrets in logs — redact with a logging.Filter on the handler

https://cwe.mitre.org/data/definitions/532.html

Logs are copied to more places (shippers, SIEM, support tickets) and kept
longer than any database, so a token that reaches a log line has leaked. Code
review cannot catch every call site, so add a last line of defence: a
logging.Filter that rewrites the final message and masks anything that looks
like a credential.

Where you attach it matters. A filter on a logger only sees records logged
*on that logger*; records from child loggers ("app.db") propagate straight to
the parent's handlers and skip it. Attach the filter to the handler, which
every record passes through. The filter formats msg % args first, because the
secret is usually in args, not in the format string.
"""

import logging
import re
import sys

PATTERNS = [
    # key=value / key: value for common credential names
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)(\s*[=:]\s*)([^\s,;&]+)"),
     r"\1\2***"),
    # Authorization: Bearer <token>
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/-]+=*"), r"\1***"),
    # userinfo in URLs: scheme://user:password@host
    (re.compile(r"(://[^/\s:@]+:)[^@\s]+@"), r"\1***@"),
    # AWS access key ids
    (re.compile(r"\b(AKIA)[0-9A-Z]{16}\b"), r"\1****************"),
]


def redact(text: str) -> str:
    for pattern, repl in PATTERNS:
        text = pattern.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None  # already merged into msg
        return True  # never drop the record, only rewrite it


def make_logger(prefix: str, on_handler: bool) -> logging.Logger:
    root = logging.getLogger(prefix)
    root.handlers.clear()
    root.propagate = False
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(f"{prefix:12} %(levelname)-7s %(name)s: %(message)s"))
    root.addHandler(handler)
    (handler if on_handler else root).addFilter(RedactingFilter())
    return root


def emit(prefix: str) -> None:
    app = logging.getLogger(prefix)
    db = logging.getLogger(f"{prefix}.db")
    app.info("login user=%s token=%s", "alice", "tok_9f8e7d6c5b4a")
    app.info("upstream call with Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig")
    db.error("connect failed: %s", "postgresql://svc:S3cr3t!pw@db.internal:5432/app")
    db.warning("s3 upload as %s to bucket backups", "AKIAIOSFODNN7EXAMPLE")


def main() -> None:
    make_logger("noncompliant", on_handler=False)  # filter on the logger
    emit("noncompliant")
    make_logger("compliant", on_handler=True)  # filter on the handler
    emit("compliant")


if __name__ == "__main__":
    main()

# Output:
# noncompliant INFO    noncompliant: login user=alice token=***
# noncompliant INFO    noncompliant: upstream call with Authorization: Bearer ***
# noncompliant ERROR   noncompliant.db: connect failed: postgresql://svc:S3cr3t!pw@db.internal:5432/app
# noncompliant WARNING noncompliant.db: s3 upload as AKIAIOSFODNN7EXAMPLE to bucket backups
# compliant    INFO    compliant: login user=alice token=***
# compliant    INFO    compliant: upstream call with Authorization: Bearer ***
# compliant    ERROR   compliant.db: connect failed: postgresql://svc:***@db.internal:5432/app
# compliant    WARNING compliant.db: s3 upload as AKIA**************** to bucket backups
