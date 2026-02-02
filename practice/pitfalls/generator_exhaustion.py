"""Generator exhaustion — the second pass over an iterator sees nothing

It is common to "save memory" by turning a list comprehension into a generator
expression or by passing ``map(...)`` straight through. That is fine until a
function consumes its argument twice: validate, then sum; count, then
average; ``if x in rows`` and then loop. An iterator can be read once. The
second pass sees an empty sequence and returns a plausible-looking wrong
value (0, an empty report) instead of raising.

Review note: check every function that iterates its parameter more than
once and every ``in`` test on an iterator. Either materialize once with
``list(...)`` at the call boundary, accept ``Sequence`` in the type hint, or
compute everything in a single pass. ``itertools.tee`` exists but buffers
everything anyway when the consumers run one after another.
"""

from collections.abc import Iterable, Sequence

LINES = ["200 12ms", "200 8ms", "500 40ms", "200 10ms"]


def parse(lines: Iterable[str]):
    return (int(line.split()[1].removesuffix("ms")) for line in lines)


def report_noncompliant(latencies: Iterable[int]) -> str:
    if any(ms < 0 for ms in latencies):          # pass 1 (stops early or exhausts)
        raise ValueError("negative latency")
    total = sum(latencies)                       # pass 2: nothing left
    return f"total={total}ms"


def report_compliant(latencies: Sequence[int]) -> str:
    if any(ms < 0 for ms in latencies):
        raise ValueError("negative latency")
    return f"total={sum(latencies)}ms count={len(latencies)}"


def main() -> None:
    print("noncompliant:", report_noncompliant(parse(LINES)))
    print("compliant:   ", report_compliant(list(parse(LINES))))

    gen = parse(LINES)
    print("40 in gen  ->", 40 in gen)
    print("list(gen)  ->", list(gen), "(the `in` test consumed everything up to 40)")

    statuses = map(lambda line: line.split()[0], LINES)
    print("first pass  :", sorted(set(statuses)))
    print("second pass :", list(statuses))

    # zip stops at the shortest input and drops the consumed element.
    it = iter(LINES)
    pairs = list(zip(it, range(2)))
    print("after zip(it, range(2)), next(it) ->", next(it), "(one line was silently lost)")
    print("pairs:", pairs)


if __name__ == "__main__":
    main()

# Output:
# noncompliant: total=0ms
# compliant:    total=70ms count=4
# 40 in gen  -> True
# list(gen)  -> [10] (the `in` test consumed everything up to 40)
# first pass  : ['200', '500']
# second pass : []
# after zip(it, range(2)), next(it) -> 200 10ms (one line was silently lost)
# pairs: [('200 12ms', 0), ('200 8ms', 1)]
