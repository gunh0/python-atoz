"""cron_expr v2 — next-run calculator, with cron's day-of-month/day-of-week OR

v1 expanded the fields; v2 answers the question people actually ask in a
change review: "when will this run next?". next_runs() walks forward from
a reference time, skipping a whole month, day or hour as soon as that field
cannot match, so even "29 February only" is found in a few thousand steps.
An expression that can never fire (31 February) raises instead of looping.

The rule everyone gets wrong: when both day-of-month and day-of-week are
restricted, cron runs when EITHER matches. `0 0 1-7 * sun` is not "first
Sunday of the month" but "days 1-7, and also every Sunday". Vixie cron and
cronie decide "restricted" by whether the field starts with `*`, so
`*/2` counts as unrestricted and is ANDed with the weekday instead.

Times are naive wall-clock times, as cron itself uses; the reference time
is fixed so the output is stable. Around DST changes real crons differ
(cronie runs a skipped 02:30 job once after the jump), so keep critical
jobs out of the 01:00-03:00 window or run the host in UTC.
"""

import datetime as dt
from dataclasses import dataclass

FIELDS = [  # name, min, max
    ("minute", 0, 59),
    ("hour", 0, 23),
    ("day of month", 1, 31),
    ("month", 1, 12),
    ("day of week", 0, 7),
]
NAMES = {
    "month": {m: i for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)},
    "day of week": {d: i for i, d in enumerate("sun mon tue wed thu fri sat".split())},
}
MACROS = {
    "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
}


WEEKDAY_NAMES = "Mon Tue Wed Thu Fri Sat Sun".split()
SEARCH_YEARS = 9  # leap days can be 8 years apart (2096 -> 2104)


class CronError(ValueError):
    pass


@dataclass(frozen=True)
class Cron:
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]
    dom_restricted: bool  # needed later: cron ORs day-of-month and day-of-week
    dow_restricted: bool


def _value(token: str, name: str, lo: int, hi: int) -> int:
    names = NAMES.get(name, {})
    if token.lower() in names:
        return names[token.lower()]
    if not token.isdigit():
        raise CronError(f"{name}: {token!r} is not a number or name")
    value = int(token)
    if not lo <= value <= hi:
        raise CronError(f"{name}: {value} is outside {lo}-{hi}")
    return value


def parse_field(text: str, name: str, lo: int, hi: int) -> set[int]:
    values: set[int] = set()
    for part in text.split(","):
        base, slash, step_text = part.partition("/")
        step = 1
        if slash:
            if not step_text.isdigit() or int(step_text) == 0:
                raise CronError(f"{name}: bad step in {part!r}")
            step = int(step_text)
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a, _, b = base.partition("-")
            start, end = _value(a, name, lo, hi), _value(b, name, lo, hi)
            if start > end:
                raise CronError(f"{name}: reversed range {base!r}")
        else:
            start = _value(base, name, lo, hi)
            end = hi if slash else start  # "5/10" means 5, 15, 25, ...
        values.update(range(start, end + 1, step))
    return values


def parse(expr: str) -> Cron:
    expr = expr.strip()
    if expr.startswith("@"):
        if expr == "@reboot":
            raise CronError("@reboot runs at boot, it has no schedule to compute")
        if expr not in MACROS:
            raise CronError(f"unknown macro {expr!r}")
        expr = MACROS[expr]
    parts = expr.split()
    if len(parts) != 5:
        raise CronError(f"expected 5 fields, got {len(parts)}")
    sets = [parse_field(p, *spec) for p, spec in zip(parts, FIELDS)]
    weekdays = {0 if d == 7 else d for d in sets[4]}
    return Cron(*(frozenset(s) for s in sets[:4]), frozenset(weekdays),
                dom_restricted=not parts[2].startswith("*"),
                dow_restricted=not parts[4].startswith("*"))


def compact(values: frozenset[int], lo: int, hi: int) -> str:
    """Render {0,1,2,3,10} as '0-3,10' and the full range as '*'."""
    if values == frozenset(range(lo, hi + 1)):
        return "*"
    items, out = sorted(values), []
    start = prev = items[0]
    for v in items[1:] + [None]:
        if v is not None and v == prev + 1:
            prev = v
            continue
        out.append(str(start) if start == prev else f"{start}-{prev}")
        if v is not None:
            start = prev = v
    return ",".join(out)


def describe(cron: Cron) -> str:
    sets = [cron.minutes, cron.hours, cron.days, cron.months, cron.weekdays]
    limits = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]
    labels = ["min", "hour", "dom", "mon", "dow"]
    return "  ".join(f"{lab}={compact(s, *lim)}" for lab, s, lim in zip(labels, sets, limits))


def day_matches(cron: Cron, t: dt.datetime) -> bool:
    dom_ok = t.day in cron.days
    dow_ok = (t.weekday() + 1) % 7 in cron.weekdays  # Python: Mon=0, cron: Sun=0
    if cron.dom_restricted and cron.dow_restricted:
        return dom_ok or dow_ok
    return dom_ok and dow_ok


def next_run(cron: Cron, after: dt.datetime) -> dt.datetime:
    """First minute strictly after `after` at which cron would start the job."""
    t = after.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    limit = after + dt.timedelta(days=366 * SEARCH_YEARS)
    while t <= limit:
        if t.month not in cron.months:
            t = (t.replace(day=1, hour=0, minute=0) + dt.timedelta(days=32)).replace(day=1)
        elif not day_matches(cron, t):
            t = t.replace(hour=0, minute=0) + dt.timedelta(days=1)
        elif t.hour not in cron.hours:
            t = t.replace(minute=0) + dt.timedelta(hours=1)
        elif t.minute not in cron.minutes:
            t += dt.timedelta(minutes=1)
        else:
            return t
    raise CronError(f"never fires within {SEARCH_YEARS} years")


def next_runs(cron: Cron, after: dt.datetime, count: int) -> list[dt.datetime]:
    runs = []
    for _ in range(count):
        after = next_run(cron, after)
        runs.append(after)
    return runs


def fmt(t: dt.datetime) -> str:
    return f"{WEEKDAY_NAMES[t.weekday()]} {t:%Y-%m-%d %H:%M}"


def main() -> None:
    now = dt.datetime(2026, 3, 14, 9, 26, 41)  # a Saturday
    print(f"reference time: {fmt(now)}:41")
    lines = [
        ("*/15 2-5 * * mon-fri", 3),
        ("@weekly", 2),
        ("30 4 1,15 * *", 3),
        ("0 0 1-7 * sun", 5),
        ("0 9 */2 * mon", 3),
        ("0 12 29 2 *", 2),
        ("0 0 31 2 *", 1),
    ]
    for expr, count in lines:
        print(f"\n{expr}   ({describe(parse(expr))})")
        try:
            for t in next_runs(parse(expr), now, count):
                print(f"  {fmt(t)}")
        except CronError as exc:
            print(f"  ERROR {exc}")


if __name__ == "__main__":
    main()

# Output:
# reference time: Sat 2026-03-14 09:26:41
#
# */15 2-5 * * mon-fri   (min=0,15,30,45  hour=2-5  dom=*  mon=*  dow=1-5)
#   Mon 2026-03-16 02:00
#   Mon 2026-03-16 02:15
#   Mon 2026-03-16 02:30
#
# @weekly   (min=0  hour=0  dom=*  mon=*  dow=0)
#   Sun 2026-03-15 00:00
#   Sun 2026-03-22 00:00
#
# 30 4 1,15 * *   (min=30  hour=4  dom=1,15  mon=*  dow=*)
#   Sun 2026-03-15 04:30
#   Wed 2026-04-01 04:30
#   Wed 2026-04-15 04:30
#
# 0 0 1-7 * sun   (min=0  hour=0  dom=1-7  mon=*  dow=0)
#   Sun 2026-03-15 00:00
#   Sun 2026-03-22 00:00
#   Sun 2026-03-29 00:00
#   Wed 2026-04-01 00:00
#   Thu 2026-04-02 00:00
#
# 0 9 */2 * mon   (min=0  hour=9  dom=1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31  mon=*  dow=1)
#   Mon 2026-03-23 09:00
#   Mon 2026-04-13 09:00
#   Mon 2026-04-27 09:00
#
# 0 12 29 2 *   (min=0  hour=12  dom=29  mon=2  dow=*)
#   Tue 2028-02-29 12:00
#   Sun 2032-02-29 12:00
#
# 0 0 31 2 *   (min=0  hour=0  dom=31  mon=2  dow=*)
#   ERROR never fires within 9 years
