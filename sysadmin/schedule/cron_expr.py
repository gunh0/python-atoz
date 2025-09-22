"""cron_expr v1 — parse a five-field cron expression into explicit value sets

Reviewing crontabs across a fleet means answering "when does this actually
run?" for lines like `*/15 2-5 * * mon-fri`. v1 is the parser: it expands
each field into the set of values it allows, which is also the best way to
find mistakes before cron silently ignores or misreads a line.

Supported, as in Vixie cron / cronie: `*`, numbers, ranges `a-b`, steps
`*/n`, `a-b/n` and `a/n` (from a to the field maximum), comma lists, month
and weekday names (jan, mon), 7 as an alias for Sunday, and the @hourly,
@daily, @weekly, @monthly and @yearly macros. Errors name the field and the
offending token. A step of 0 and reversed ranges like 5-2 are rejected
(some crons accept them with surprising results). @reboot has no times and
is reported as such rather than guessed at.
"""

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


def main() -> None:
    lines = [
        "*/15 2-5 * * mon-fri",
        "0 3 * * 7",
        "30 4 1,15 * *",
        "5/20 * * jan-mar,dec *",
        "@weekly",
        "0 0 1-7 * sun",
        "0 24 * * *",
        "*/0 * * * *",
        "0 5-2 * * *",
        "0 9 * * tuesday",
        "15 3 * *",
        "@reboot",
    ]
    for line in lines:
        try:
            print(f"{line:<24} {describe(parse(line))}")
        except CronError as exc:
            print(f"{line:<24} ERROR {exc}")


if __name__ == "__main__":
    main()

# Output:
# */15 2-5 * * mon-fri     min=0,15,30,45  hour=2-5  dom=*  mon=*  dow=1-5
# 0 3 * * 7                min=0  hour=3  dom=*  mon=*  dow=0
# 30 4 1,15 * *            min=30  hour=4  dom=1,15  mon=*  dow=*
# 5/20 * * jan-mar,dec *   min=5,25,45  hour=*  dom=*  mon=1-3,12  dow=*
# @weekly                  min=0  hour=0  dom=*  mon=*  dow=0
# 0 0 1-7 * sun            min=0  hour=0  dom=1-7  mon=*  dow=0
# 0 24 * * *               ERROR hour: 24 is outside 0-23
# */0 * * * *              ERROR minute: bad step in '*/0'
# 0 5-2 * * *              ERROR hour: reversed range '5-2'
# 0 9 * * tuesday          ERROR day of week: 'tuesday' is not a number or name
# 15 3 * *                 ERROR expected 5 fields, got 4
# @reboot                  ERROR @reboot runs at boot, it has no schedule to compute
