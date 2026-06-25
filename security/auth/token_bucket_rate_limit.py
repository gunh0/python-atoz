"""CWE-307: login rate limiting — token buckets keyed by IP *and* by account

https://cwe.mitre.org/data/definitions/307.html

The quick limiter is a counter per IP that resets every minute. It allows a
double burst at each window edge (5 requests at 59.9 s, 5 more at 60.0 s),
and keying only by IP does nothing against credential stuffing, where a
botnet tries one password per address against the same account.

A token bucket refills continuously, so the burst is bounded by its capacity
at every instant. Keep one bucket per client IP and one per target account:
an attacker spreading guesses across addresses still drains the account's
bucket. Time comes from an injected clock in integer milliseconds and the
refill math uses Fraction, so the decisions are exact and testable.
"""

from collections import defaultdict
from fractions import Fraction


class FakeClock:
    def __init__(self) -> None:
        self.ms = 0

    def advance_to(self, ms: int) -> None:
        self.ms = ms


class FixedWindow:
    def __init__(self, clock: FakeClock, limit: int, window_ms: int) -> None:
        self.clock, self.limit, self.window_ms = clock, limit, window_ms
        self.counts: dict[tuple[str, int], int] = defaultdict(int)

    def allow(self, key: str) -> bool:
        slot = (key, self.clock.ms // self.window_ms)
        self.counts[slot] += 1
        return self.counts[slot] <= self.limit


class TokenBucket:
    def __init__(self, clock: FakeClock, capacity: int, per_ms: int) -> None:
        """Hold up to `capacity` tokens; regain one token every `per_ms` milliseconds."""
        self.clock, self.capacity = clock, Fraction(capacity)
        self.rate = Fraction(1, per_ms)
        self.state: dict[str, tuple[Fraction, int]] = {}

    def available(self, key: str) -> Fraction:
        now = self.clock.ms
        tokens, last = self.state.get(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        self.state[key] = (tokens, now)
        return tokens

    def allow(self, key: str) -> bool:
        tokens = self.available(key)
        if tokens >= 1:
            self.state[key] = (tokens - 1, self.clock.ms)
            return True
        return False


class LoginLimiter:
    def __init__(self, clock: FakeClock) -> None:
        self.per_ip = TokenBucket(clock, capacity=5, per_ms=12_000)  # 5/min sustained
        self.per_account = TokenBucket(clock, capacity=5, per_ms=12_000)

    def allow(self, ip: str, username: str) -> bool:
        account = f"user:{username}"
        if self.per_ip.available(ip) < 1 or self.per_account.available(account) < 1:
            return False  # refuse without charging either bucket
        return self.per_ip.allow(ip) and self.per_account.allow(account)


def main() -> None:
    clock = FakeClock()
    window = FixedWindow(clock, limit=5, window_ms=60_000)
    bucket = TokenBucket(clock, capacity=5, per_ms=12_000)
    burst = range(59_000, 61_000, 100)  # 20 requests in two seconds, across a minute edge
    allowed_window = allowed_bucket = 0
    for t in burst:
        clock.advance_to(t)
        allowed_window += window.allow("203.0.113.7")
        allowed_bucket += bucket.allow("203.0.113.7")
    print(f"noncompliant: fixed window let {allowed_window} of {len(burst)} through in 2 s")
    print(f"compliant:    token bucket let {allowed_bucket} of {len(burst)} through in 2 s")

    clock.advance_to(61_000 + 36_000)  # 36 s later: three tokens back
    print(f"compliant:    after 36 s quiet, next 5 attempts -> "
          f"{['ok' if bucket.allow('203.0.113.7') else 'no' for _ in range(5)]}")

    clock = FakeClock()
    by_ip_only = TokenBucket(clock, capacity=5, per_ms=12_000)
    both = LoginLimiter(clock)
    ips = [f"198.51.100.{i}" for i in range(1, 51)]  # credential stuffing from 50 addresses
    reached_ip_only = sum(by_ip_only.allow(ip) for ip in ips)
    reached_both = sum(both.allow(ip, "alice") for ip in ips)
    print(f"noncompliant: per-IP buckets only, guesses reaching alice: {reached_ip_only} of 50")
    print(f"compliant:    per-IP + per-account, guesses reaching alice: {reached_both} of 50")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: fixed window let 10 of 20 through in 2 s
# compliant:    token bucket let 5 of 20 through in 2 s
# compliant:    after 36 s quiet, next 5 attempts -> ['ok', 'ok', 'ok', 'no', 'no']
# noncompliant: per-IP buckets only, guesses reaching alice: 50 of 50
# compliant:    per-IP + per-account, guesses reaching alice: 5 of 50
