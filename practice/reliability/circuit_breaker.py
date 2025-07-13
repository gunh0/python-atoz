"""Circuit breaker — stop hammering a dependency that is already down

https://martinfowler.com/bliki/CircuitBreaker.html

Retries help with blips; during a real outage they multiply load on the very
service that is struggling, and every caller waits for its own timeout. The
usual answer to "make the client resilient" is more retries. What I ask
for in review instead is a breaker in front of the call:

  CLOSED     calls go through; consecutive failures are counted
  OPEN       after N failures, fail fast without calling the dependency
  HALF_OPEN  after a cool-down, let one trial call through; success closes
             the breaker, failure opens it again for another cool-down

The clock is injected so the whole outage is replayed in a loop, with the
same output every run.
"""

from typing import Callable


class Clock:
    def __init__(self) -> None:
        self.now = 0.0


class Backend:
    """Down between t=10 and t=40, healthy otherwise."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.hits = 0

    def __call__(self) -> str:
        self.hits += 1
        if 10 <= self.clock.now < 40:
            raise ConnectionError("upstream unavailable")
        return "200"


class CircuitOpen(Exception):
    pass


class CircuitBreaker:
    def __init__(self, clock: Clock, threshold: int = 3, cooldown: float = 12.0) -> None:
        self.clock = clock
        self.threshold = threshold
        self.cooldown = cooldown
        self.state = "CLOSED"
        self.failures = 0
        self.opened_at = 0.0

    def call(self, fn: Callable[[], str]) -> str:
        if self.state == "OPEN":
            if self.clock.now - self.opened_at < self.cooldown:
                raise CircuitOpen("fail fast")
            self.state = "HALF_OPEN"  # cool-down over: allow one trial
        try:
            result = fn()
        except Exception:
            self._failure()
            raise
        self.state, self.failures = "CLOSED", 0
        return result

    def _failure(self) -> None:
        self.failures += 1
        if self.state == "HALF_OPEN" or self.failures >= self.threshold:
            self.state, self.opened_at = "OPEN", self.clock.now


def outcome(fn: Callable[[], str]) -> str:
    try:
        return fn()
    except CircuitOpen:
        return "fast-fail"
    except ConnectionError:
        return "error"


def main() -> None:
    ticks = range(0, 70, 4)  # one request every 4 s

    clock = Clock()
    backend = Backend(clock)
    plain = []
    for t in ticks:
        clock.now = t
        plain.append(outcome(backend))
    plain_hits = backend.hits

    clock = Clock()
    backend = Backend(clock)
    breaker = CircuitBreaker(clock)
    rows = []
    for t in ticks:
        clock.now = t
        before = backend.hits
        result = outcome(lambda: breaker.call(backend))
        rows.append((t, result, breaker.state, backend.hits > before))

    print("   t  no breaker | with breaker  state after  reached backend")
    for (t, result, state, reached), raw in zip(rows, plain):
        print(f"{t:>4}  {raw:<10} | {result:<12}  {state:<11}  {'yes' if reached else '-'}")
    print()
    print(f"noncompliant: backend called {plain_hits} times, "
          f"{plain.count('error')} of them during the outage")
    print(f"compliant:    backend called {backend.hits} times, "
          f"{sum(r[1] == 'error' for r in rows)} errors, "
          f"{sum(r[1] == 'fast-fail' for r in rows)} answered instantly")


if __name__ == "__main__":
    main()

# Output:
#    t  no breaker | with breaker  state after  reached backend
#    0  200        | 200           CLOSED       yes
#    4  200        | 200           CLOSED       yes
#    8  200        | 200           CLOSED       yes
#   12  error      | error         CLOSED       yes
#   16  error      | error         CLOSED       yes
#   20  error      | error         OPEN         yes
#   24  error      | fast-fail     OPEN         -
#   28  error      | fast-fail     OPEN         -
#   32  error      | error         OPEN         yes
#   36  error      | fast-fail     OPEN         -
#   40  200        | fast-fail     OPEN         -
#   44  200        | 200           CLOSED       yes
#   48  200        | 200           CLOSED       yes
#   52  200        | 200           CLOSED       yes
#   56  200        | 200           CLOSED       yes
#   60  200        | 200           CLOSED       yes
#   64  200        | 200           CLOSED       yes
#   68  200        | 200           CLOSED       yes
#
# noncompliant: backend called 18 times, 7 of them during the outage
# compliant:    backend called 14 times, 4 errors, 4 answered instantly
