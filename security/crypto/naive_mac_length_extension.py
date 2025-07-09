"""CWE-327: sha256(secret + message) is not a MAC — length extension, and why HMAC exists

https://cwe.mitre.org/data/definitions/327.html

SHA-256 is a Merkle-Damgard hash: the digest *is* the internal state after the
last block. Given sha256(secret + msg) and the length of secret + msg, anyone
can resume hashing from that state and compute sha256(secret + msg + padding +
extra) without knowing the secret. For a signed query string that means
appending "&role=admin" and producing a valid tag. The secret length is not a
real obstacle; the attacker tries each length against the verifier.

HMAC hashes twice with the key mixed into both passes, so the outer hash hides
the inner state and nothing can be appended. Use hmac.new(key, msg, sha256)
(SHA-3 and BLAKE2 also resist extension, but HMAC is the interoperable choice).
"""

import hashlib
import hmac
import math
import struct

SECRET = b"k3y-only-the-api-server-knows"  # length unknown to the attacker

# SHA-256 constants, derived instead of pasted: fractional bits of roots of primes.
PRIMES = [p for p in range(2, 312) if all(p % d for d in range(2, math.isqrt(p) + 1))][:64]


def _icbrt(n: int) -> int:
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


K = [_icbrt(p << 96) & 0xFFFFFFFF for p in PRIMES]
H0 = [math.isqrt(p << 64) & 0xFFFFFFFF for p in PRIMES[:8]]


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _compress(state: list[int], block: bytes) -> list[int]:
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        t1 = h + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]
        t2 = (_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
        a, b, c, d, e, f, g, h = (t1 + t2) & 0xFFFFFFFF, a, b, c, (d + t1) & 0xFFFFFFFF, e, f, g
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def md_padding(length: int) -> bytes:
    return b"\x80" + b"\x00" * ((55 - length) % 64) + struct.pack(">Q", length * 8)


def sha256(data: bytes, state: list[int] | None = None, prefix_len: int = 0) -> bytes:
    """Plain SHA-256, or SHA-256 resumed from `state` after `prefix_len` bytes."""
    state = list(state or H0)
    data += md_padding(prefix_len + len(data))
    for i in range(0, len(data), 64):
        state = _compress(state, data[i:i + 64])
    return struct.pack(">8I", *state)


def noncompliant_sign(msg: bytes) -> str:
    return hashlib.sha256(SECRET + msg).hexdigest()


def noncompliant_verify(msg: bytes, tag: str) -> bool:
    return hmac.compare_digest(noncompliant_sign(msg), tag)


def compliant_sign(msg: bytes) -> str:
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()


def compliant_verify(msg: bytes, tag: str) -> bool:
    return hmac.compare_digest(compliant_sign(msg), tag)


def extend(msg: bytes, tag: str, extra: bytes, secret_len: int) -> tuple[bytes, str]:
    glue = md_padding(secret_len + len(msg))
    state = list(struct.unpack(">8I", bytes.fromhex(tag)))
    forged_tag = sha256(extra, state, prefix_len=secret_len + len(msg) + len(glue))
    return msg + glue + extra, forged_tag.hex()


def attack(msg: bytes, tag: str, verify) -> tuple[int, bytes] | None:
    for guess in range(1, 65):
        forged_msg, forged_tag = extend(msg, tag, b"&role=admin", guess)
        if verify(forged_msg, forged_tag):
            return guess, forged_msg
    return None


def role_of(query: bytes) -> str:
    pairs = [p.split(b"=", 1) for p in query.split(b"&") if b"=" in p]
    return dict(pairs)[b"role"].decode()  # last value wins, as in many parsers


def main() -> None:
    print(f"own sha256 == hashlib: {sha256(b'abc' * 50) == hashlib.sha256(b'abc' * 50).digest()}")
    msg = b"user=alice&role=viewer"

    tag = noncompliant_sign(msg)
    secret_len, forged = attack(msg, tag, noncompliant_verify)
    print(f"noncompliant: tag accepted for forged message, secret length guessed = {secret_len}")
    print(f"noncompliant: forged message {forged!r}")
    print(f"noncompliant: server reads role = {role_of(forged)}")

    tag = compliant_sign(msg)
    print(f"compliant:    forgery found = {attack(msg, tag, compliant_verify) is not None}")
    print(f"compliant:    server reads role = {role_of(msg)}")


if __name__ == "__main__":
    main()

# Output:
# own sha256 == hashlib: True
# noncompliant: tag accepted for forged message, secret length guessed = 29
# noncompliant: forged message b'user=alice&role=viewer\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x98&role=admin'
# noncompliant: server reads role = admin
# compliant:    forgery found = False
# compliant:    server reads role = viewer
