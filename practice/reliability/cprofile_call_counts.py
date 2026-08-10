"""cProfile + pstats — find the hot spot by call counts, not by guessing

https://docs.python.org/3/library/profile.html

Code under review is usually correct on the happy path and quietly wasteful: the
config is re-parsed for every log line, a regex is compiled inside the loop, a
helper is called three times per record "for clarity". Nobody notices on the
ten-line sample. Before optimising anything, profile it.

Timings vary between machines and runs, but call counts do not, and they
usually point straight at the problem: a function called once per record that
should be called once per run. `pstats.Stats(...).sort_stats("calls", "name")`
puts the busiest functions first ("name" breaks ties so the order is stable).
This demo prints only function names and counts; in real use
`print_stats(10)` shows the times as well.
"""

import cProfile
import json
import pstats
import re

RULES_JSON = '{"alert": ["ERROR", "CRIT"], "ignore": ["healthcheck"]}'
LOG = [
    "2026-09-30T10:00:01 INFO GET /healthcheck 200",
    "2026-09-30T10:00:02 ERROR db timeout after 30s",
    "2026-09-30T10:00:03 INFO GET /api/orders 200",
    "2026-09-30T10:00:04 CRIT disk /var full",
] * 250


def load_rules() -> dict:
    return json.loads(RULES_JSON)


def classify(line: str, rules: dict) -> str:
    if any(word in line for word in rules["ignore"]):
        return "ignore"
    level = re.compile(r"^\S+ (\w+) ").match(line).group(1)
    return "alert" if level in rules["alert"] else "info"


def noncompliant(lines: list[str]) -> int:
    alerts = 0
    for line in lines:
        rules = load_rules()  # re-parsed for every line
        alerts += classify(line, rules) == "alert"
    return alerts


LEVEL = re.compile(r"^\S+ (\w+) ")


def classify_fast(line: str, rules: dict) -> str:
    if any(word in line for word in rules["ignore"]):
        return "ignore"
    return "alert" if LEVEL.match(line).group(1) in rules["alert"] else "info"


def compliant(lines: list[str]) -> int:
    rules = load_rules()  # once per run
    return sum(classify_fast(line, rules) == "alert" for line in lines)


WATCH = {"load_rules", "classify", "classify_fast", "loads", "compile", "noncompliant", "compliant"}


def profile(fn, lines: list[str]) -> None:
    profiler = cProfile.Profile()
    result = profiler.runcall(fn, lines)
    stats = pstats.Stats(profiler).sort_stats("calls", "name")
    print(f"{fn.__name__}: {result} alerts in {len(lines)} lines")
    for func in stats.fcn_list:  # sorted by sort_stats()
        _file, _line, name = func
        if name in WATCH:
            primitive_calls = stats.stats[func][0]
            print(f"  {primitive_calls:>6}  {name}")


def main() -> None:
    profile(noncompliant, LOG)
    profile(compliant, LOG)


if __name__ == "__main__":
    main()

# Output:
# noncompliant: 500 alerts in 1000 lines
#     1000  classify
#     1000  load_rules
#     1000  loads
#      750  compile
#        1  noncompliant
# compliant: 500 alerts in 1000 lines
#     1000  classify_fast
#        1  compliant
#        1  load_rules
#        1  loads
