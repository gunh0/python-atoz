"""Naive vs aware datetimes — a timestamp without a zone means "whatever this machine thinks"

A common idiom parses log lines and API fields with ``datetime.fromisoformat``
or ``strptime`` and then compares, subtracts or calls ``.timestamp()``. If the string
had no offset, the result is *naive*: Python does not know which zone it is in.
``.timestamp()`` on a naive value silently assumes the host's local zone, so the
same code gives different epoch seconds on a laptop in Seoul and a CI runner in
UTC. Ordering comparisons between naive and aware values raise ``TypeError``,
but ``==`` quietly returns False, which hides the bug in dedup logic.

Review note: decide the zone at the boundary where data enters (log format,
API contract) and attach it once with ``replace(tzinfo=...)``; keep everything
aware afterwards, store and compare in UTC. Treat ``tzinfo is None`` past the
parsing layer as a bug.
"""

import os
import time
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

LOG_LINE_TS = "2024-05-01T09:00:00"            # app log, written in KST, no offset
API_TS = "2024-05-01T00:00:00+00:00"           # same instant, from an API, with offset


def epoch_noncompliant(ts: str) -> float:
    return datetime.fromisoformat(ts).timestamp()   # uses the host zone


def epoch_compliant(ts: str, source_zone: ZoneInfo) -> float:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=source_zone)
    return dt.timestamp()


def with_host_zone(zone: str, func, *args):
    old = os.environ.get("TZ")
    os.environ["TZ"] = zone
    time.tzset()
    try:
        return func(*args)
    finally:
        if old is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = old
        time.tzset()


def main() -> None:
    seoul = ZoneInfo("Asia/Seoul")
    for host in ("UTC", "Asia/Seoul", "America/New_York"):
        bad = with_host_zone(host, epoch_noncompliant, LOG_LINE_TS)
        good = with_host_zone(host, epoch_compliant, LOG_LINE_TS, seoul)
        print(f"host TZ={host:<17} noncompliant {bad:.0f}   compliant {good:.0f}")

    naive = datetime.fromisoformat(LOG_LINE_TS)
    aware = datetime.fromisoformat(API_TS)
    print("naive == aware ->", naive == aware, "(no error, just a wrong answer)")
    try:
        naive < aware
    except TypeError as exc:
        print("naive < aware  -> TypeError:", exc)

    fixed = naive.replace(tzinfo=seoul)
    print("compliant: same instant?", fixed == aware)
    print("compliant: in UTC       ", fixed.astimezone(UTC).isoformat())


if __name__ == "__main__":
    main()

# Output:
# host TZ=UTC               noncompliant 1714554000   compliant 1714521600
# host TZ=Asia/Seoul        noncompliant 1714521600   compliant 1714521600
# host TZ=America/New_York  noncompliant 1714568400   compliant 1714521600
# naive == aware -> False (no error, just a wrong answer)
# naive < aware  -> TypeError: can't compare offset-naive and offset-aware datetimes
# compliant: same instant? True
# compliant: in UTC        2024-05-01T00:00:00+00:00
