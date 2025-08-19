"""``datetime.utcnow()`` — deprecated since 3.12, and naive in a way that bites

``datetime.utcnow()`` and ``datetime.utcfromtimestamp()`` are all over old
tutorials and answers, so they still show up in new code. They return a *naive* datetime whose
fields happen to be UTC. Nothing in the object says so, and the first time it
meets ``.timestamp()``, ``astimezone()`` or an aware value, Python treats it as
local time. On a UTC CI runner every test passes; on a developer laptop in
Seoul the epoch is nine hours off.

Review note: replace with ``datetime.now(UTC)`` and
``datetime.fromtimestamp(ts, UTC)``. Run tests with ``-W error::DeprecationWarning``
so new uses fail, and run at least one job with a non-UTC ``TZ``. The example
uses a fixed epoch instead of "now" so the output is reproducible.
"""

import os
import time
import warnings
from datetime import UTC, datetime

EPOCH = 1_700_000_000  # 2023-11-14T22:13:20Z


def to_epoch_noncompliant(ts: int) -> float:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        dt = datetime.utcfromtimestamp(ts)       # naive, fields are UTC
    return dt.timestamp()                        # ...interpreted as local time


def to_epoch_compliant(ts: int) -> float:
    return datetime.fromtimestamp(ts, UTC).timestamp()


def main() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        now = datetime.utcnow()
    w = caught[0]
    first, _, advice = str(w.message).partition(". ")
    print(f"{w.category.__name__}: {first}.")
    print(f"  advice: {advice}")
    print("utcnow().tzinfo      =", now.tzinfo)
    print("now(UTC).tzinfo      =", datetime.now(UTC).tzinfo)

    for zone in ("UTC", "Asia/Seoul"):
        os.environ["TZ"] = zone
        time.tzset()
        bad = to_epoch_noncompliant(EPOCH)
        good = to_epoch_compliant(EPOCH)
        print(f"TZ={zone:<10} noncompliant {bad:.0f} (off by {bad - EPOCH:+.0f}s)"
              f"   compliant {good:.0f}")

    print("compliant isoformat  =", datetime.fromtimestamp(EPOCH, UTC).isoformat())


if __name__ == "__main__":
    main()

# Output:
# DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version.
#   advice: Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
# utcnow().tzinfo      = None
# now(UTC).tzinfo      = UTC
# TZ=UTC        noncompliant 1700000000 (off by +0s)   compliant 1700000000
# TZ=Asia/Seoul noncompliant 1699967600 (off by -32400s)   compliant 1700000000
# compliant isoformat  = 2023-11-14T22:13:20+00:00
