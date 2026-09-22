"""The big-O trap — `x in some_list` inside a loop is quadratic

https://wiki.python.org/moin/TimeComplexity

It is easy to reach for lists by default: `seen = []` and
`if ip not in seen: seen.append(ip)`, or
`[u for u in users if u not in blocked]` with `blocked` a list. Each `in` on a
list compares against every element until it finds a match, so a loop over n
items does up to n * m comparisons. With the 50-row sample it is instant; with
last month's 200k log lines it is the batch job that never finishes.

A set or dict lookup hashes the value once and compares with (almost always)
one candidate. Counting the work makes this visible without a stopwatch: the
`Probe` wrapper below counts every `__eq__` and `__hash__` call, so the numbers
are identical on every machine. Note that dedup with a set also needs order
kept: `dict.fromkeys(items)` does both.
"""

import random


class Probe:
    eq_calls = 0
    hash_calls = 0

    def __init__(self, value: int) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        Probe.eq_calls += 1
        return isinstance(other, Probe) and self.value == other.value

    def __hash__(self) -> int:
        Probe.hash_calls += 1
        return hash(self.value)


def dedupe_noncompliant(items: list[Probe]) -> list[Probe]:
    seen: list[Probe] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def dedupe_compliant(items: list[Probe]) -> list[Probe]:
    return list(dict.fromkeys(items))  # insertion order kept


def filter_noncompliant(users: list[Probe], blocked: list[Probe]) -> list[Probe]:
    return [u for u in users if u not in blocked]


def filter_compliant(users: list[Probe], blocked: list[Probe]) -> list[Probe]:
    blocked_set = set(blocked)
    return [u for u in users if u not in blocked_set]


def count(fn, *args) -> tuple[int, int, int]:
    Probe.eq_calls = Probe.hash_calls = 0
    result = fn(*args)
    return len(result), Probe.eq_calls, Probe.hash_calls


def main() -> None:
    rng = random.Random(1)
    print(f"{'dedupe n':>9} {'unique':>7} {'list ==':>11} {'dict ==':>8} {'dict hash':>10}")
    for n in (100, 1_000, 4_000):
        items = [Probe(rng.randrange(n // 2)) for _ in range(n)]
        unique, slow_eq, _ = count(dedupe_noncompliant, items)
        unique_fast, fast_eq, fast_hash = count(dedupe_compliant, items)
        assert unique == unique_fast
        print(f"{n:>9} {unique:>7} {slow_eq:>11,} {fast_eq:>8,} {fast_hash:>10,}")
    print()
    print(f"{'filter n':>9} {'blocked':>7} {'list ==':>11} {'set ==':>8} {'set hash':>10}")
    for n in (100, 1_000, 4_000):
        users = [Probe(i) for i in range(n)]
        blocked = [Probe(i) for i in rng.sample(range(n), n // 10)]
        kept, slow_eq, _ = count(filter_noncompliant, users, blocked)
        kept_fast, fast_eq, fast_hash = count(filter_compliant, users, blocked)
        assert kept == kept_fast
        print(f"{n:>9} {len(blocked):>7} {slow_eq:>11,} {fast_eq:>8,} {fast_hash:>10,}")
    print("\n10x more rows -> about 100x more comparisons with lists, about 10x with sets")


if __name__ == "__main__":
    main()

# Output:
#  dedupe n  unique     list ==  dict ==  dict hash
#       100      46       2,084       54        100
#      1000     436     192,031      564      1,000
#      4000    1721   2,983,949    2,279      4,000
#
#  filter n blocked     list ==   set ==   set hash
#       100      10         955       10        110
#      1000     100      95,050      100      1,100
#      4000     400   1,520,200      400      4,400
#
# 10x more rows -> about 100x more comparisons with lists, about 10x with sets
