"""DST transitions with zoneinfo — "one day later" is not always 24 hours

For "the next run, one day later" or "how long did the job run" it is easy
to write ``start + timedelta(days=1)`` and ``end - start`` on aware
datetimes and move on. Python does wall-clock arithmetic when both values share
the same ``tzinfo``: adding a day keeps the local time, and subtracting ignores
the offset change. Across a DST switch that is off by an hour. Local times in
the spring-forward gap do not exist, and times in the fall-back hour happen
twice; ``fold`` picks which one.

Review note: for elapsed time and "N hours later", convert to UTC, do the
arithmetic there, then convert back. Use local wall-clock arithmetic only when
the requirement really is "same local time tomorrow". Scheduler code must say
what happens to a 02:30 job on the spring-forward day. Dates below are fixed
(US transitions in 2024: March 10 and November 3).
"""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

NY = ZoneInfo("America/New_York")


def elapsed_noncompliant(start: datetime, end: datetime) -> timedelta:
    return end - start                      # same tzinfo -> wall-clock difference


def elapsed_compliant(start: datetime, end: datetime) -> timedelta:
    return end.astimezone(UTC) - start.astimezone(UTC)


def add_hours_noncompliant(start: datetime, hours: int) -> datetime:
    return start + timedelta(hours=hours)


def add_hours_compliant(start: datetime, hours: int) -> datetime:
    return (start.astimezone(UTC) + timedelta(hours=hours)).astimezone(start.tzinfo)


def show(label: str, *values) -> None:
    print(f"{label:<22}", *values)


def main() -> None:
    start = datetime(2024, 3, 9, 12, 0, tzinfo=NY)
    end = start + timedelta(days=1)
    show("start", start.isoformat())
    show("start + 1 day", end.isoformat())
    show("noncompliant elapsed", elapsed_noncompliant(start, end))
    show("compliant elapsed", elapsed_compliant(start, end))
    show("noncompliant +24h", add_hours_noncompliant(start, 24).isoformat())
    show("compliant +24h", add_hours_compliant(start, 24).isoformat())

    # 02:30 on 2024-03-10 never happened in New York.
    gap = datetime(2024, 3, 10, 2, 30, tzinfo=NY)
    roundtrip = gap.astimezone(UTC).astimezone(NY)
    show("gap 02:30", gap.isoformat(), "-> really", roundtrip.strftime("%H:%M %Z"))

    # 01:30 on 2024-11-03 happened twice.
    for fold in (0, 1):
        t = datetime(2024, 11, 3, 1, 30, fold=fold, tzinfo=NY)
        show(f"fold={fold} 01:30", t.isoformat(), t.tzname(),
             "=", t.astimezone(UTC).strftime("%H:%M UTC"))

    # Same tzinfo -> == compares wall clock and ignores fold. Only UTC tells them apart.
    a = datetime(2024, 11, 3, 1, 30, fold=0, tzinfo=NY)
    b = datetime(2024, 11, 3, 1, 30, fold=1, tzinfo=NY)
    show("fold=0 == fold=1", a == b, "  compared in UTC:", a.astimezone(UTC) == b.astimezone(UTC))


if __name__ == "__main__":
    main()

# Output:
# start                  2024-03-09T12:00:00-05:00
# start + 1 day          2024-03-10T12:00:00-04:00
# noncompliant elapsed   1 day, 0:00:00
# compliant elapsed      23:00:00
# noncompliant +24h      2024-03-10T12:00:00-04:00
# compliant +24h         2024-03-10T13:00:00-04:00
# gap 02:30              2024-03-10T02:30:00-05:00 -> really 03:30 EDT
# fold=0 01:30           2024-11-03T01:30:00-04:00 EDT = 05:30 UTC
# fold=1 01:30           2024-11-03T01:30:00-05:00 EST = 06:30 UTC
# fold=0 == fold=1       True   compared in UTC: False
