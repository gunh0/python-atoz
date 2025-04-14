"""Retries with exponential backoff and jitter — and a clock you can inject

https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/

The retry loop most people write first is `while True: try: ... except
Exception: time.sleep(1)`. It looks resilient. In production it retries bugs
that will never succeed (a ValueError is not transient), never gives up, and
when a dependency blips every client sleeps exactly one second and comes back
at the same instant — a self-made thundering herd.

The reviewer should ask for: an allow-list of transient exceptions, a bounded
number of attempts, exponentially growing delays with a cap, random jitter so
clients spread out, and the clock/sleep and random source passed in. The last
point is what makes the policy testable: the demo below "sleeps" for minutes
without waiting at all and prints the same numbers on every run.
"""

import random
from collections import Counter
from typing import Callable


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class Flaky:
    """Fails with the given exceptions in order, then returns 'ok'."""

    def __init__(self, failures: list[Exception]) -> None:
        self.failures = list(failures)
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        return "ok"


def noncompliant(op: Callable[[], str], clock: FakeClock, max_loops: int = 20) -> str:
    # `while True` in the original; max_loops only keeps this demo finite.
    for _ in range(max_loops):
        try:
            return op()
        except Exception:
            clock.sleep(1)
    return "still retrying..."


TRANSIENT = (ConnectionError, TimeoutError)


def compliant(op: Callable[[], str], clock: FakeClock, rng: random.Random,
              attempts: int = 5, base: float = 0.5, cap: float = 8.0) -> str:
    for attempt in range(attempts):
        try:
            return op()
        except TRANSIENT:
            if attempt == attempts - 1:
                raise
            # "Full jitter": anywhere between 0 and the exponential ceiling.
            clock.sleep(rng.uniform(0, min(cap, base * 2 ** attempt)))
    raise AssertionError("unreachable")


def main() -> None:
    clock = FakeClock()
    op = Flaky([ConnectionError()] * 2)
    print(f"noncompliant: transient x2 -> {noncompliant(op, clock)!r} after {op.calls} calls")
    clock = FakeClock()
    op = Flaky([ValueError("bad input")] * 99)
    print(f"noncompliant: ValueError   -> {noncompliant(op, clock)!r} "
          f"after {op.calls} calls, slept {clock.now:.0f}s")

    # Ten clients hit the same outage; when does each one retry first?
    herd = Counter()
    for _ in range(10):
        clock = FakeClock()
        noncompliant(Flaky([ConnectionError()]), clock)
        herd[clock.sleeps[0]] += 1
    print(f"noncompliant: 10 clients retry at {dict(herd)} -> all at the same second")
    print()

    clock = FakeClock()
    op = Flaky([ConnectionError(), TimeoutError(), ConnectionError()])
    result = compliant(op, clock, random.Random(42))
    print(f"compliant:    transient x3 -> {result!r} after {op.calls} calls, "
          f"sleeps {[round(s, 2) for s in clock.sleeps]}")

    clock = FakeClock()
    op = Flaky([ValueError("bad input")])
    try:
        compliant(op, clock, random.Random(42))
    except ValueError as exc:
        print(f"compliant:    ValueError   -> raised {exc!r} after {op.calls} call, no sleep")

    clock = FakeClock()
    op = Flaky([ConnectionError()] * 99)
    try:
        compliant(op, clock, random.Random(42))
    except ConnectionError:
        print(f"compliant:    outage       -> gave up after {op.calls} calls, "
              f"ceilings {[min(8.0, 0.5 * 2 ** a) for a in range(4)]}")

    # Real clients use random.Random() (OS-seeded); seeding per client keeps the demo stable.
    firsts = []
    for client in range(10):
        clock = FakeClock()
        compliant(Flaky([ConnectionError()]), clock, random.Random(client))
        firsts.append(round(clock.sleeps[0], 2))
    print(f"compliant:    10 clients first retry spread over {sorted(firsts)}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: transient x2 -> 'ok' after 3 calls
# noncompliant: ValueError   -> 'still retrying...' after 20 calls, slept 20s
# noncompliant: 10 clients retry at {1: 10} -> all at the same second
#
# compliant:    transient x3 -> 'ok' after 4 calls, sleeps [0.32, 0.03, 0.55]
# compliant:    ValueError   -> raised ValueError('bad input') after 1 call, no sleep
# compliant:    outage       -> gave up after 5 calls, ceilings [0.5, 1.0, 2.0, 4.0]
# compliant:    10 clients first retry spread over [0.07, 0.11, 0.12, 0.12, 0.16, 0.23, 0.31, 0.4, 0.42, 0.48]
