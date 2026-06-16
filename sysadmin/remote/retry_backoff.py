"""Retries with exponential backoff, jitter and a deadline — on a fake clock

A remote call that fails once is normal (a deploy restarting the service, a
full accept queue). `for i in range(3): try ... except: time.sleep(1)` is the
usual answer and gets three things wrong: it retries errors that will never
succeed, it hammers a struggling service at a fixed rate, and when 200
hosts run it from the same cron minute they all retry in the same second.

retry() below retries only errors the caller marks as transient, doubles
the delay each time up to a cap, optionally applies "full jitter" (sleep a
random time between 0 and the delay) so clients spread out, and stops when
the next sleep would cross an overall deadline, re-raising the last error.

Time is injected: the clock's sleep() only advances a number, so the whole
schedule runs instantly and the output is exact. Jitter uses a seeded
random.Random for the same reason; in production pass random.Random().
"""

import random


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class GaveUp(Exception):
    pass


def retry(op, *, clock, transient=(ConnectionError, TimeoutError), attempts=6, base=0.5, cap=8.0,
          deadline=30.0, rng: random.Random | None = None, log=print):
    start = clock.time()
    for attempt in range(attempts):
        try:
            return op()
        except transient as exc:
            last = exc
            delay = min(cap, base * 2 ** attempt)
            if rng is not None:
                delay = rng.uniform(0, delay)
            if attempt == attempts - 1:
                break
            if clock.time() + delay - start > deadline:
                log(f"  t={clock.time():6.2f}  {type(exc).__name__}; next wait {delay:.2f}s would pass the deadline")
                break
            log(f"  t={clock.time():6.2f}  {type(exc).__name__}: {exc}; retry in {delay:.2f}s")
            clock.sleep(delay)
    raise GaveUp(f"gave up after {attempt + 1} attempt(s)") from last


def flaky(clock, failures, error=ConnectionRefusedError, cost=0.1):
    """An operation that fails `failures` times, each call taking `cost` seconds."""
    state = {"calls": 0}

    def op():
        clock.sleep(cost)
        state["calls"] += 1
        if state["calls"] <= failures:
            raise error("connection refused" if error is ConnectionRefusedError else "denied")
        return f"ok after {state['calls']} call(s)"

    return op


def scenario(title, op_factory, **kw) -> None:
    clock = FakeClock()
    print(title)
    try:
        result = retry(op_factory(clock), clock=clock, **kw)
        print(f"  t={clock.time():6.2f}  {result}")
    except GaveUp as exc:
        print(f"  t={clock.time():6.2f}  {exc}; cause: {type(exc.__cause__).__name__}")
    except Exception as exc:
        print(f"  t={clock.time():6.2f}  not retried: {type(exc).__name__}: {exc}")


def herd(clients: int, rng_for) -> list[list]:
    """Times at which each client retries a service that is down for 10 s."""
    times = []
    for c in range(clients):
        clock, seen = FakeClock(), []
        def op():
            seen.append(round(clock.time(), 2))
            if clock.time() < 10:
                raise ConnectionRefusedError("down")
            return "up"
        try:
            retry(op, clock=clock, rng=rng_for(c), attempts=8, log=lambda msg: None)
        except GaveUp:
            seen.append("gave up")
        times.append(seen)
    return times


def main() -> None:
    scenario("service restarting (3 failures):", lambda c: flaky(c, 3))
    scenario("same, with full jitter:", lambda c: flaky(c, 3), rng=random.Random(7))
    scenario("permission problem (not transient):", lambda c: flaky(c, 3, error=PermissionError))
    scenario("down for good, 10 s deadline:", lambda c: flaky(c, 99), deadline=10.0)
    print()
    print("4 clients, service down for 10 s; call times per client")
    for label, rng_for in (("no jitter", lambda c: None), ("full jitter", lambda c: random.Random(100 + c))):
        print(f"  {label}:")
        for c, seen in enumerate(herd(4, rng_for)):
            print(f"    client {c}: " + " ".join(f"{t:5.2f}" if isinstance(t, float) else t for t in seen))


if __name__ == "__main__":
    main()

# Output:
# service restarting (3 failures):
#   t=  0.10  ConnectionRefusedError: connection refused; retry in 0.50s
#   t=  0.70  ConnectionRefusedError: connection refused; retry in 1.00s
#   t=  1.80  ConnectionRefusedError: connection refused; retry in 2.00s
#   t=  3.90  ok after 4 call(s)
# same, with full jitter:
#   t=  0.10  ConnectionRefusedError: connection refused; retry in 0.16s
#   t=  0.36  ConnectionRefusedError: connection refused; retry in 0.15s
#   t=  0.61  ConnectionRefusedError: connection refused; retry in 1.30s
#   t=  2.01  ok after 4 call(s)
# permission problem (not transient):
#   t=  0.10  not retried: PermissionError: denied
# down for good, 10 s deadline:
#   t=  0.10  ConnectionRefusedError: connection refused; retry in 0.50s
#   t=  0.70  ConnectionRefusedError: connection refused; retry in 1.00s
#   t=  1.80  ConnectionRefusedError: connection refused; retry in 2.00s
#   t=  3.90  ConnectionRefusedError: connection refused; retry in 4.00s
#   t=  8.00  ConnectionRefusedError; next wait 8.00s would pass the deadline
#   t=  8.00  gave up after 5 attempt(s); cause: ConnectionRefusedError
#
# 4 clients, service down for 10 s; call times per client
#   no jitter:
#     client 0:  0.00  0.50  1.50  3.50  7.50 15.50
#     client 1:  0.00  0.50  1.50  3.50  7.50 15.50
#     client 2:  0.00  0.50  1.50  3.50  7.50 15.50
#     client 3:  0.00  0.50  1.50  3.50  7.50 15.50
#   full jitter:
#     client 0:  0.00  0.07  0.53  2.07  4.89 10.75
#     client 1:  0.00  0.29  0.49  2.42  6.11  9.85 15.16
#     client 2:  0.00  0.07  0.69  1.03  3.88  8.74 11.82
#     client 3:  0.00  0.49  0.95  2.38  5.32  7.04  7.67 12.49
