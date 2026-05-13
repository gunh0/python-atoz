"""logging for admin scripts — handlers, formatters, filters, rotation

print() is fine until a cron job has to send its summary to the terminal,
its details to a file that cannot fill the disk, and its errors somewhere
someone will look. The logging module does that with one logger and
several handlers, each with its own level and formatter:

- console (stdout): INFO and up, short format for humans
- run.log: DEBUG and up, RotatingFileHandler capped at 200 bytes here
  (megabytes in real life), keeping two old files; older lines are dropped
- errors.log: ERROR only, one line per error, exception included

Two filters show what filters are for. One masks secrets (password=...)
before any handler sees the record, because log files get attached to
tickets. The other pins record timestamps to the job's sample clock so this
example prints the same output every run; in production you let logging
stamp the records. Exceptions are formatted on one line (type: message) so
a single grep shows them. propagate=False keeps a root logger configured by
some library from printing everything twice.
"""

import logging
import logging.handlers
import re
import sys
import tempfile
import time
from pathlib import Path


class RedactSecrets(logging.Filter):
    PATTERN = re.compile(r"(password|token|secret)=\S+", re.IGNORECASE)

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.PATTERN.sub(r"\1=***", record.getMessage())
        record.args = None
        return True


class SampleClock(logging.Filter):
    """Stamp records with a scripted time (reproducible output only)."""

    def __init__(self, start: float) -> None:
        super().__init__()
        self.now = start

    def filter(self, record: logging.LogRecord) -> bool:
        record.created, record.msecs = self.now, 0.0
        self.now += 7
        return True


class OneLineFormatter(logging.Formatter):
    converter = time.gmtime  # log in UTC, say so in the format

    def formatException(self, ei) -> str:
        return f"{ei[0].__name__}: {ei[1]}"

    def format(self, record: logging.LogRecord) -> str:
        # Formatter caches the rendered exception on the record; another
        # handler's formatter may have cached a multi-line traceback there.
        cached, record.exc_text = record.exc_text, None
        try:
            return super().format(record).replace("\n", " | ")
        finally:
            record.exc_text = cached


def build_logger(log_dir: Path) -> logging.Logger:
    logger = logging.getLogger("nightly-backup")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addFilter(RedactSecrets())
    logger.addFilter(SampleClock(start=1773453600))  # 2026-03-14 02:00:00 UTC

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(OneLineFormatter("%(levelname)-7s %(message)s"))

    detail = OneLineFormatter("%(asctime)sZ %(host)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    run_log = logging.handlers.RotatingFileHandler(log_dir / "run.log", maxBytes=200, backupCount=2,
                                                   encoding="utf-8")
    run_log.setLevel(logging.DEBUG)
    run_log.setFormatter(detail)

    errors = logging.FileHandler(log_dir / "errors.log", encoding="utf-8")
    errors.setLevel(logging.ERROR)
    errors.setFormatter(detail)

    for handler in (console, run_log, errors):
        logger.addHandler(handler)
    return logger


def nightly_backup(log: logging.LoggerAdapter) -> None:
    log.info("backup started")
    log.debug("connecting to %s with password=%s", "db-01", "hunter2")
    for table, rows in (("users", 1204), ("orders", 88210), ("audit", 1530221)):
        log.debug("dumped %s: %d rows", table, rows)
    log.warning("audit table larger than 1M rows, consider partitioning")
    try:
        raise OSError(28, "No space left on device")
    except OSError:
        log.exception("upload to %s failed", "https://nas01/upload?token=9f8e7d6c")
    log.info("backup finished with errors")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        log_dir = Path(tmp)
        logger = build_logger(log_dir)
        nightly_backup(logging.LoggerAdapter(logger, {"host": "db-01"}))
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)

        print()
        kept = 0
        for path in sorted(log_dir.iterdir()):
            lines = path.read_text(encoding="utf-8").splitlines()
            kept += len(lines) if path.name.startswith("run.log") else 0
            print(f"{path.name:<10} {len(lines)} line(s)")
        print(f"run.log* keeps {kept} of 8 records; the oldest were rotated away")
        print("\nerrors.log:")
        print((log_dir / "errors.log").read_text(encoding="utf-8"), end="")
        print("\nrun.log.2 (oldest kept):")
        print((log_dir / "run.log.2").read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()

# Output:
# INFO    backup started
# WARNING audit table larger than 1M rows, consider partitioning
# ERROR   upload to https://nas01/upload?token=*** failed | OSError: [Errno 28] No space left on device
# INFO    backup finished with errors
#
# errors.log 1 line(s)
# run.log    2 line(s)
# run.log.1  1 line(s)
# run.log.2  2 line(s)
# run.log* keeps 5 of 8 records; the oldest were rotated away
#
# errors.log:
# 2026-03-14T02:00:42Z db-01 ERROR upload to https://nas01/upload?token=*** failed | OSError: [Errno 28] No space left on device
#
# run.log.2 (oldest kept):
# 2026-03-14T02:00:21Z db-01 DEBUG dumped orders: 88210 rows
# 2026-03-14T02:00:28Z db-01 DEBUG dumped audit: 1530221 rows
