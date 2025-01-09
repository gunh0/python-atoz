"""CWE-338: weak PRNG for security tokens — use secrets, never random

https://cwe.mitre.org/data/definitions/338.html

The random module is a Mersenne Twister: fast, reproducible, and completely
predictable. If a password-reset token comes from random, an attacker who can
guess the seed (often the process start time) regenerates the same token
offline. Even without the seed, 624 consecutive 32-bit outputs reveal the whole
internal state, so every future "token" can be computed in advance.

secrets draws from the operating system CSPRNG (os.urandom). It cannot be
seeded, so there is nothing to guess and nothing to recover. Use
secrets.token_urlsafe / token_hex / token_bytes for anything an attacker must
not predict, and keep random for simulations and tests.
"""

import random
import secrets
import string

ALPHABET = string.ascii_letters + string.digits
SERVER_START = 1_700_000_000  # what time.time() returned when the app booted


def noncompliant_reset_token(rng: random.Random) -> str:
    return "".join(rng.choices(ALPHABET, k=20))


def guess_seed(token: str, around: int, window: int = 3600) -> int | None:
    """Attacker: try every boot second within an hour of the guessed time."""
    for seed in range(around - window, around + window):
        if noncompliant_reset_token(random.Random(seed)) == token:
            return seed
    return None


def _untemper(y: int) -> int:
    """Invert the MT19937 output tempering for one 32-bit word."""
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    t = y
    for _ in range(5):
        t = y ^ ((t << 7) & 0x9D2C5680)
    y = t
    t = y
    for _ in range(2):
        t = y ^ (t >> 11)
    return t & 0xFFFFFFFF


def clone_from_outputs(outputs: list[int]) -> random.Random:
    """Rebuild a Random instance from 624 observed getrandbits(32) values."""
    state = tuple(_untemper(v) for v in outputs[:624])
    clone = random.Random()
    clone.setstate((3, state + (624,), None))
    return clone


def compliant_reset_token() -> str:
    return secrets.token_urlsafe(32)  # 32 random bytes -> 43 url-safe chars


def main() -> None:
    # 1. Seeded by boot time: the attacker only needs a rough guess.
    server = random.Random(SERVER_START)
    victim_token = noncompliant_reset_token(server)
    found = guess_seed(victim_token, around=SERVER_START - 1200)
    print(f"noncompliant: victim token      {victim_token}")
    print(f"noncompliant: seed recovered    {found}")
    print(f"noncompliant: token regenerated {noncompliant_reset_token(random.Random(found))}")

    # 2. Unknown seed: observe 624 session ids, then predict the next ones.
    server = random.Random(0xC0FFEE)
    observed = [server.getrandbits(32) for _ in range(624)]
    clone = clone_from_outputs(observed)
    real_next = [server.getrandbits(32) for _ in range(3)]
    predicted = [clone.getrandbits(32) for _ in range(3)]
    print(f"noncompliant: next ids          {[f'{v:08x}' for v in real_next]}")
    print(f"noncompliant: predicted ids     {[f'{v:08x}' for v in predicted]}")
    print(f"noncompliant: next reset token  {noncompliant_reset_token(server)}")
    print(f"noncompliant: predicted token   {noncompliant_reset_token(clone)}")

    # 3. secrets: output differs on every run, so only its properties are printed.
    token = compliant_reset_token()
    print(f"compliant:    token length      {len(token)}")
    print(f"compliant:    url-safe chars    {set(token) <= set(ALPHABET + '-_')}")
    print(f"compliant:    1000 unique       {len({compliant_reset_token() for _ in range(1000)}) == 1000}")
    sysrand = random.SystemRandom()
    sysrand.seed(42)  # silently ignored: the OS CSPRNG has no seed to set
    a = sysrand.getrandbits(128)
    sysrand.seed(42)
    print(f"compliant:    seed() ignored    {a != sysrand.getrandbits(128)}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: victim token      tlhYQQyPnb47RZMJrchI
# noncompliant: seed recovered    1700000000
# noncompliant: token regenerated tlhYQQyPnb47RZMJrchI
# noncompliant: next ids          ['8af483d9', '2c957f86', 'fd2c7151']
# noncompliant: predicted ids     ['8af483d9', '2c957f86', 'fd2c7151']
# noncompliant: next reset token  Ej2k6vaieNZqoWp4jfFU
# noncompliant: predicted token   Ej2k6vaieNZqoWp4jfFU
# compliant:    token length      43
# compliant:    url-safe chars    True
# compliant:    1000 unique       True
# compliant:    seed() ignored    True
