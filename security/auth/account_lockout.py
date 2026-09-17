"""CWE-307/CWE-645: account lockout — temporary, escalating, and checked before the password

https://cwe.mitre.org/data/definitions/307.html    (CWE-645: https://cwe.mitre.org/data/definitions/645.html)

Two lockout bugs show up again and again. A permanent lock after N failures
lets anyone lock any account they can name: five wrong guesses and the CEO
cannot log in until the helpdesk opens. And a lock that is checked only
*after* a wrong password ("if bad password: count it; if count > 5: say
locked") still lets the right password in, so the attacker keeps guessing and
simply ignores the "locked" responses.

The compliant policy checks the lock first and refuses even a correct
password while it lasts, locks temporarily (1 minute, doubling to a 1 hour
cap), forgets failures after 15 quiet minutes, resets on success, and gives
the same answer for "wrong password" and "locked" so the response leaks
nothing. Pair it with the per-IP rate limit from token_bucket_rate_limit.py.
"""

from dataclasses import dataclass

PASSWORDS = {"alice": "Summer2024!", "bob": "correct horse"}  # stands in for verify_password()
MAX_FAILURES = 5
BASE_LOCK, MAX_LOCK, FORGET_AFTER = 60, 3600, 15 * 60


class FakeClock:
    def __init__(self) -> None:
        self.now = 0

    def tick(self, seconds: int) -> int:
        self.now += seconds
        return self.now


class NoncompliantPermanentLockout:
    def __init__(self, clock: FakeClock) -> None:
        self.failures: dict[str, int] = {}

    def login(self, user: str, password: str) -> str:
        if self.failures.get(user, 0) >= MAX_FAILURES:
            return "locked (call helpdesk)"
        if PASSWORDS.get(user) == password:
            return "ok"
        self.failures[user] = self.failures.get(user, 0) + 1
        return "wrong password"


class NoncompliantLockAfterCheck:
    def __init__(self, clock: FakeClock) -> None:
        self.failures: dict[str, int] = {}

    def login(self, user: str, password: str) -> str:
        if PASSWORDS.get(user) == password:
            return "ok"  # the lock is never consulted on the success path
        self.failures[user] = self.failures.get(user, 0) + 1
        return "locked" if self.failures[user] >= MAX_FAILURES else "wrong password"


@dataclass
class State:
    failures: int = 0
    last_failure: int = 0
    locks: int = 0
    locked_until: int = 0


class CompliantLockout:
    def __init__(self, clock: FakeClock) -> None:
        self.clock, self.state = clock, {}

    def login(self, user: str, password: str) -> str:
        now = self.clock.now
        st = self.state.setdefault(user, State())
        if now < st.locked_until:
            return "denied"  # do not even look at the password
        if st.failures and now - st.last_failure > FORGET_AFTER:
            st.failures = 0
        if PASSWORDS.get(user) == password:
            self.state[user] = State()
            return "ok"
        st.failures, st.last_failure = st.failures + 1, now
        if st.failures >= MAX_FAILURES:
            st.locked_until = now + min(MAX_LOCK, BASE_LOCK * 2**st.locks)
            st.locks, st.failures = st.locks + 1, 0
        return "denied"  # identical for wrong password and locked


def scenario(policy_cls) -> list[str]:
    clock = FakeClock()
    policy = policy_cls(clock)
    out = []
    for _ in range(MAX_FAILURES):  # attacker: five wrong guesses for alice
        policy.login("alice", "guess")
        clock.tick(1)
    out.append(f"alice right after 5 bad guesses -> {policy.login('alice', 'Summer2024!')}")
    clock.tick(59)  # a minute later
    out.append(f"alice one minute later         -> {policy.login('alice', 'Summer2024!')}")
    for round_ in range(2):  # bob: five guesses, wait out the lock, five more
        for _ in range(MAX_FAILURES):
            policy.login("bob", "guess")
            clock.tick(1)
        if round_ == 0:
            clock.tick(BASE_LOCK)
    clock.tick(60)
    out.append(f"bob 1 min after 2nd lockout    -> {policy.login('bob', 'correct horse')}")
    clock.tick(60)
    out.append(f"bob 2 min after 2nd lockout    -> {policy.login('bob', 'correct horse')}")
    return out


def main() -> None:
    for label, cls in (("permanent", NoncompliantPermanentLockout), ("after-check", NoncompliantLockAfterCheck),
                       ("compliant", CompliantLockout)):
        for line in scenario(cls):
            print(f"{label + ':':12} {line}")

    clock = FakeClock()
    policy = NoncompliantLockAfterCheck(clock)
    guesses = ["123456", "password", "qwerty", "letmein", "dragon", "monkey", "Summer2024!"]
    results = [policy.login("alice", g) for g in guesses]
    print(f"after-check: guess #{len(guesses)} after lock -> {results[-1]} (lock never applied)")
    clock = FakeClock()
    policy = CompliantLockout(clock)
    results = [policy.login("alice", g) for g in guesses]
    print(f"compliant:   guess #{len(guesses)} after lock -> {results[-1]}, responses seen: {sorted(set(results))}")


if __name__ == "__main__":
    main()

# Output:
# permanent:   alice right after 5 bad guesses -> locked (call helpdesk)
# permanent:   alice one minute later         -> locked (call helpdesk)
# permanent:   bob 1 min after 2nd lockout    -> locked (call helpdesk)
# permanent:   bob 2 min after 2nd lockout    -> locked (call helpdesk)
# after-check: alice right after 5 bad guesses -> ok
# after-check: alice one minute later         -> ok
# after-check: bob 1 min after 2nd lockout    -> ok
# after-check: bob 2 min after 2nd lockout    -> ok
# compliant:   alice right after 5 bad guesses -> denied
# compliant:   alice one minute later         -> ok
# compliant:   bob 1 min after 2nd lockout    -> denied
# compliant:   bob 2 min after 2nd lockout    -> ok
# after-check: guess #7 after lock -> ok (lock never applied)
# compliant:   guess #7 after lock -> denied, responses seen: ['denied']
