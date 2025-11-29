"""CWE-384: session fixation — rotate the session id at login, store only its hash

https://cwe.mitre.org/data/definitions/384.html

If the session id a browser had *before* login stays valid *after* login, an
attacker who planted that id (a link with ?sid=..., a cookie set from a
sibling subdomain, a shared kiosk) is logged in as the victim the moment the
victim signs in. Servers that adopt any id a client sends make planting easy.

The compliant store issues ids only from secrets.token_urlsafe, refuses ids it
did not issue, rotates the id on every privilege change (login, sudo,
logout), and enforces idle and absolute timeouts against an injected clock.
It keys sessions by sha256(id), so a leaked session table holds no usable
cookies. Real ids are random, so the output shows them as S1, S2, ...
"""

import hashlib
import secrets
from dataclasses import dataclass

IDLE_TIMEOUT = 30 * 60
ABSOLUTE_TIMEOUT = 8 * 3600


class Clock:
    def __init__(self, now: int = 1_750_000_000) -> None:
        self.now = now

    def advance(self, seconds: int) -> None:
        self.now += seconds


@dataclass
class Session:
    user: str | None
    created: int
    last_seen: int


class NoncompliantStore:
    def __init__(self, clock: Clock) -> None:
        self.clock, self.sessions = clock, {}

    def get_or_create(self, sid: str) -> str:
        self.sessions.setdefault(sid, Session(None, self.clock.now, self.clock.now))
        return sid  # adopts whatever id the client sent

    def login(self, sid: str, user: str) -> str:
        self.sessions[sid].user = user  # same id, now authenticated
        return sid

    def whoami(self, sid: str) -> str:
        session = self.sessions.get(sid)
        return session.user if session and session.user else "anonymous"


class CompliantStore:
    def __init__(self, clock: Clock) -> None:
        self.clock, self.sessions = clock, {}

    @staticmethod
    def _key(sid: str) -> str:
        return hashlib.sha256(sid.encode()).hexdigest()

    def _issue(self, user: str | None) -> str:
        sid = secrets.token_urlsafe(32)
        self.sessions[self._key(sid)] = Session(user, self.clock.now, self.clock.now)
        return sid

    def get_or_create(self, sid: str | None) -> str:
        if sid is None or self._lookup(sid) is None:
            return self._issue(None)  # unknown id: ignore it and issue our own
        return sid

    def _lookup(self, sid: str) -> Session | None:
        session = self.sessions.get(self._key(sid))
        if session is None:
            return None
        now = self.clock.now
        if now - session.last_seen > IDLE_TIMEOUT or now - session.created > ABSOLUTE_TIMEOUT:
            del self.sessions[self._key(sid)]
            return None
        session.last_seen = now
        return session

    def login(self, sid: str, user: str) -> str:
        self.sessions.pop(self._key(sid), None)  # the pre-login id dies here
        return self._issue(user)

    def logout(self, sid: str) -> None:
        self.sessions.pop(self._key(sid), None)

    def whoami(self, sid: str) -> str:
        session = self._lookup(sid)
        if session is None:
            return "rejected"
        return session.user or "anonymous"


class Labels:
    """Show random ids as S1, S2, ... in order of first appearance."""

    def __init__(self) -> None:
        self.names: dict[str, str] = {}

    def __call__(self, sid: str) -> str:
        return self.names.setdefault(sid, f"S{len(self.names) + 1}")


def main() -> None:
    clock = Clock()
    store = NoncompliantStore(clock)
    planted = store.get_or_create("attacker-chosen-id")
    victim = store.login(planted, "alice")
    print(f"noncompliant: planted id adopted, victim logs in on it: same id = {victim == planted}")
    print(f"noncompliant: attacker uses planted id -> {store.whoami(planted)}")

    clock, label = Clock(), Labels()
    store = CompliantStore(clock)
    first = store.get_or_create("attacker-chosen-id")
    print(f"compliant:    client sent unknown id, server issued {label(first)}")
    victim = store.login(first, "alice")
    print(f"compliant:    login rotates {label(first)} -> {label(victim)}")
    print(f"compliant:    old id {label(first)} -> {store.whoami(first)}")
    print(f"compliant:    new id {label(victim)} -> {store.whoami(victim)}")
    print(f"compliant:    table keys are sha256(id): {all(len(k) == 64 for k in store.sessions)}, "
          f"raw id stored: {victim in store.sessions}")

    clock.advance(IDLE_TIMEOUT + 1)
    print(f"compliant:    {label(victim)} after 30 min idle -> {store.whoami(victim)}")

    busy = store.login(store.get_or_create(None), "bob")
    states = []
    for _ in range(17):  # active every 29 minutes, yet capped at 8 hours
        clock.advance(29 * 60)
        states.append(store.whoami(busy))
    print(f"compliant:    {label(busy)} active every 29 min: at 7h44m -> {states[-2]}, at 8h13m -> {states[-1]}")

    again = store.login(store.get_or_create(None), "carol")
    store.logout(again)
    print(f"compliant:    {label(again)} after logout -> {store.whoami(again)}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: planted id adopted, victim logs in on it: same id = True
# noncompliant: attacker uses planted id -> alice
# compliant:    client sent unknown id, server issued S1
# compliant:    login rotates S1 -> S2
# compliant:    old id S1 -> rejected
# compliant:    new id S2 -> alice
# compliant:    table keys are sha256(id): True, raw id stored: False
# compliant:    S2 after 30 min idle -> rejected
# compliant:    S3 active every 29 min: at 7h44m -> bob, at 8h13m -> rejected
# compliant:    S4 after logout -> rejected
