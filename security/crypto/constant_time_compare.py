"""CWE-208: timing side channel — compare MACs and tokens with hmac.compare_digest

https://cwe.mitre.org/data/definitions/208.html

`expected == received` stops at the first differing byte, so the time it takes
tells the caller how many leading bytes were right. Over a network that signal
is noisy, but with enough samples it is measurable, and it turns a 16^16 guess
into 16 rounds of 16 guesses.

Timing numbers are not reproducible, so this example counts the work instead:
each comparator reports how many byte positions it examined, which is exactly
what the timing would reveal. The early-exit compare leaks the matching prefix
and the attacker rebuilds the tag; the constant-time compare examines every
position every time and gives the attacker nothing. In real code call
hmac.compare_digest(a, b) on bytes (or ASCII-only str).
"""

import hashlib
import hmac
import string

KEY = b"server-side signing key, never sent to clients"
HEX = string.hexdigits[:16]  # 0-9a-f


def noncompliant_equal(a: str, b: str) -> tuple[bool, int]:
    """Early exit, like == on str/bytes. Returns (equal, positions examined)."""
    if len(a) != len(b):
        return False, 0
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return False, i + 1
    return True, len(a)


def compliant_equal(a: str, b: str) -> tuple[bool, int]:
    """Same shape as hmac.compare_digest: OR together every difference."""
    if len(a) != len(b):
        return False, 0  # length is not secret here: tags are fixed-size
    diff = 0
    for x, y in zip(a.encode(), b.encode()):
        diff |= x ^ y
    return diff == 0, len(a)


def recover_tag(compare, expected: str) -> tuple[str, int]:
    """Attacker: for each position pick the char that made the server work hardest."""
    known, queries = "", 0
    for pos in range(len(expected)):
        best, best_work = HEX[0], -1
        for c in HEX:
            guess = (known + c).ljust(len(expected), "0")
            ok, work = compare(expected, guess)
            queries += 1
            if ok:
                return guess, queries
            if work > best_work:
                best, best_work = c, work
        known += best
    return known, queries


def main() -> None:
    tag = hmac.new(KEY, b"user=alice;role=admin", hashlib.sha256).hexdigest()[:16]
    print(f"secret tag    {tag}")
    for label, compare in (("noncompliant:", noncompliant_equal), ("compliant:   ", compliant_equal)):
        found, queries = recover_tag(compare, tag)
        print(f"{label} recovered {found} after {queries} queries, forged={found == tag}")

    print(f"work per guess, early exit:    {[noncompliant_equal(tag, g)[1] for g in ('0' * 16, tag[:5] + '0' * 11, tag[:12] + '0000')]}")
    print(f"work per guess, constant time: {[compliant_equal(tag, g)[1] for g in ('0' * 16, tag[:5] + '0' * 11, tag[:12] + '0000')]}")
    print(f"hmac.compare_digest(tag, tag)  {hmac.compare_digest(tag.encode(), tag.encode())}")
    try:
        hmac.compare_digest("café", "café")
    except TypeError as exc:
        print(f"non-ASCII str rejected:        {exc}")


if __name__ == "__main__":
    main()

# Output:
# secret tag    14435f58f2f70310
# noncompliant: recovered 14435f58f2f70310 after 226 queries, forged=True
# compliant:    recovered 0000000000000000 after 256 queries, forged=False
# work per guess, early exit:    [1, 6, 14]
# work per guess, constant time: [16, 16, 16]
# hmac.compare_digest(tag, tag)  True
# non-ASCII str rejected:        comparing strings with non-ASCII characters is not supported
