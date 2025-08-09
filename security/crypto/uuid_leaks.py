"""CWE-340: predictable identifiers — uuid1 leaks time and MAC, uuid4 does not

https://cwe.mitre.org/data/definitions/340.html

uuid1 is not random. It is a 60-bit timestamp (100 ns ticks since 1582-10-15),
a 14-bit clock sequence that stays fixed for the process, and the 48-bit node,
which is usually the host's MAC address. Anyone holding one uuid1 learns when
and on which machine it was made.

Used as a password-reset or invite token it is guessable: the attacker
requests a token, triggers one for the victim, requests another, and the
victim's token is one of the few thousand ticks in between with the same clock
sequence and node. uuid4 is 122 bits from os.urandom; it is a fine opaque ID.
For secrets, secrets.token_urlsafe() says what you mean.
"""

import datetime
import time
import uuid

GREGORIAN_OFFSET = 0x01B21DD213814000  # 100 ns ticks from 1582-10-15 to 1970-01-01
NODE = 0x0242AC110002  # 02:42:ac:11:00:02, a Docker bridge MAC
CLOCK_SEQ = 0x2B7E


def make_uuid1(unix_ticks: int) -> uuid.UUID:
    """Build the uuid1 the library would produce at this instant (fixed for the example)."""
    t = unix_ticks + GREGORIAN_OFFSET
    return uuid.UUID(fields=(t & 0xFFFFFFFF, (t >> 32) & 0xFFFF, ((t >> 48) & 0x0FFF) | 0x1000,
                             ((CLOCK_SEQ >> 8) & 0x3F) | 0x80, CLOCK_SEQ & 0xFF, NODE))


def decode(u: uuid.UUID) -> tuple[str, str]:
    unix_us = (u.time - GREGORIAN_OFFSET) // 10
    when = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC) + datetime.timedelta(microseconds=unix_us)
    mac = ":".join(f"{(u.node >> s) & 0xFF:02x}" for s in range(40, -8, -8))
    return when.isoformat(), mac


def sandwich(before: uuid.UUID, after: uuid.UUID) -> list[uuid.UUID]:
    """Every uuid1 that could have been issued between two tokens the attacker holds."""
    return [make_uuid1(t - GREGORIAN_OFFSET) for t in range(before.time + 1, after.time)]


def main() -> None:
    base = 1_709_629_953 * 10_000_000 + 1_234_560  # 2024-03-05T09:12:33.123456Z, 100 ns ticks
    attacker_1 = make_uuid1(base)
    victim = make_uuid1(base + 1_337)  # issued 133.7 us later, never seen by the attacker
    attacker_2 = make_uuid1(base + 2_048)

    when, mac = decode(attacker_1)
    print(f"noncompliant: token          {attacker_1}  (version {attacker_1.version})")
    print(f"noncompliant: issued at      {when}")
    print(f"noncompliant: issued by MAC  {mac}")
    candidates = sandwich(attacker_1, attacker_2)
    print(f"noncompliant: candidates     {len(candidates)} between the attacker's two tokens")
    print(f"noncompliant: victim found   {victim in candidates} at index {candidates.index(victim)}")
    real = uuid.uuid1(node=NODE, clock_seq=CLOCK_SEQ)  # the library, right now
    age_s = abs((real.time - GREGORIAN_OFFSET) / 1e7 - time.time())
    print(f"noncompliant: uuid.uuid1()   same layout: node={real.node == NODE}, "
          f"clock_seq={real.clock_seq == CLOCK_SEQ}, time is now: {age_s < 60}")

    tokens = [uuid.uuid4() for _ in range(1000)]
    print(f"compliant:    versions       {sorted({t.version for t in tokens})}, variant {tokens[0].variant}")
    print(f"compliant:    random bits    {128 - 6} per uuid4 (6 fixed version/variant bits)")
    print(f"compliant:    all distinct   {len(set(tokens)) == 1000}")
    print(f"compliant:    time field     meaningless: {len({t.time for t in tokens}) == 1000}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: token          8009ad00-dad0-11ee-ab7e-0242ac110002  (version 1)
# noncompliant: issued at      2024-03-05T09:12:33.123456+00:00
# noncompliant: issued by MAC  02:42:ac:11:00:02
# noncompliant: candidates     2047 between the attacker's two tokens
# noncompliant: victim found   True at index 1336
# noncompliant: uuid.uuid1()   same layout: node=True, clock_seq=True, time is now: True
# compliant:    versions       [4], variant specified in RFC 4122
# compliant:    random bits    122 per uuid4 (6 fixed version/variant bits)
# compliant:    all distinct   True
# compliant:    time field     meaningless: True
