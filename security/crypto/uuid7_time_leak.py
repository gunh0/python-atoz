# requires-python: >=3.14
"""CWE-340: uuid.uuid7() (Python 3.14) — great primary key, poor public ID, no token

https://cwe.mitre.org/data/definitions/340.html    (RFC 9562: https://www.rfc-editor.org/rfc/rfc9562)

Python 3.14 added uuid.uuid7(): a 48-bit Unix timestamp in milliseconds,
then a 42-bit counter, then 32 random bits. Because the IDs sort by creation
time they keep B-tree indexes compact, which is why teams switch primary keys
to it. The same property means anyone holding an ID can read when the row was
created (a signup date, an order rate), and IDs minted in the same
millisecond differ by counter + 1 and only 32 fresh random bits, compared
with 122 for uuid4.

Keep uuid7 for internal keys. Give the outside world a separate uuid4 or a
secrets.token_urlsafe() value, and never use either UUID as a password reset
or session secret. This unit needs Python 3.14 for uuid.uuid7().
"""

import datetime
import time
import uuid


def decode_v7(u: uuid.UUID) -> tuple[str, int, int]:
    ms = u.int >> 80
    counter = ((u.int >> 64) & 0x0FFF) << 30 | (u.int >> 32) & 0x3FFF_FFFF
    when = datetime.datetime.fromtimestamp(ms / 1000, datetime.UTC).isoformat(timespec="milliseconds")
    return when, counter, u.int & 0xFFFF_FFFF


def main() -> None:
    leaked = uuid.UUID("01909e4b-1d58-7a3c-9f21-6b0e5d4c3a29")  # an order id from a public URL
    when, _, _ = decode_v7(leaked)
    print(f"noncompliant: public order id {leaked} (version {leaked.version})")
    print(f"noncompliant: created at      {when}")

    ids = [uuid.uuid7() for _ in range(2000)]  # a burst, as in a bulk insert
    decoded = [decode_v7(u) for u in ids]
    same_ms = [(a, b) for a, b in zip(decoded, decoded[1:]) if a[0] == b[0]]
    print(f"noncompliant: ids sort by creation time: {ids == sorted(ids)}")
    print(f"noncompliant: same-ms neighbours differ by counter + 1: "
          f"{bool(same_ms) and all(b[1] == a[1] + 1 for a, b in same_ms)}")
    print(f"noncompliant: unknown bits in a same-ms neighbour: 32 (uuid4: 122)")
    age = time.time() - (ids[-1].int >> 80) / 1000
    print(f"noncompliant: timestamp of a fresh id is 'now': {abs(age) < 60}")

    order = {"pk": uuid.uuid7(), "public_id": uuid.uuid4()}
    print(f"compliant:    internal pk version {order['pk'].version}, "
          f"exposed public_id version {order['public_id'].version}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: public order id 01909e4b-1d58-7a3c-9f21-6b0e5d4c3a29 (version 7)
# noncompliant: created at      2024-07-10T20:17:21.240+00:00
# noncompliant: ids sort by creation time: True
# noncompliant: same-ms neighbours differ by counter + 1: True
# noncompliant: unknown bits in a same-ms neighbour: 32 (uuid4: 122)
# noncompliant: timestamp of a fresh id is 'now': True
# compliant:    internal pk version 7, exposed public_id version 4
