"""CWE-328: weak hashes — hashlib basics, usedforsecurity, and digest misuse

https://cwe.mitre.org/data/definitions/328.html

Most hash bugs are not "someone picked MD5". They are a truncated digest used
as an ID (32 bits collide after ~65,000 items by the birthday bound), or fields
glued together before hashing so ("ab", "c") and ("a", "bc") give the same key.

The safe habits: use SHA-256 or BLAKE2 and keep the full digest; encode
structured input unambiguously (length-prefix every field); stream large
inputs with update() or hashlib.file_digest(). When you hash for a non-security
reason (cache keys, dedup), say so with usedforsecurity=False: FIPS builds
then still allow MD5, and reviewers can see the intent.
"""

import hashlib
import io


def noncompliant_short_id(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()[:8]  # 32 bits: birthday collision ~2**16


def find_collision() -> tuple[bytes, bytes, str]:
    seen: dict[str, bytes] = {}
    i = 0
    while True:
        doc = f"invoice-{i}".encode()
        short = noncompliant_short_id(doc)
        if short in seen:
            return seen[short], doc, short
        seen[short] = doc
        i += 1


def noncompliant_key(*fields: str) -> str:
    return hashlib.sha256("".join(fields).encode()).hexdigest()


def compliant_key(*fields: str) -> str:
    h = hashlib.sha256()
    for field in fields:
        raw = field.encode()
        h.update(len(raw).to_bytes(4, "big"))  # length prefix makes boundaries explicit
        h.update(raw)
    return h.hexdigest()


def main() -> None:
    # Known-answer tests (FIPS 180-2 / FIPS 202 "abc" vectors).
    print(f"sha256('abc')   {hashlib.sha256(b'abc').hexdigest()}")
    print(f"sha3_256('abc') {hashlib.sha3_256(b'abc').hexdigest()}")
    print(f"md5('abc')      {hashlib.md5(b'abc', usedforsecurity=False).hexdigest()}")

    h = hashlib.sha256()
    for chunk in (b"a", b"b", b"c"):
        h.update(chunk)
    print(f"incremental == one-shot: {h.hexdigest() == hashlib.sha256(b'abc').hexdigest()}")
    stream = io.BytesIO(b"abc" * 100_000)
    print(f"file_digest(sha256)      {hashlib.file_digest(stream, 'sha256').hexdigest()[:16]}...")

    keyed = hashlib.blake2b(b"abc", key=b"k" * 32, digest_size=16, person=b"cache-v1")
    print(f"blake2b keyed, 16 bytes  {keyed.hexdigest()}")
    print(f"shake_128, 10 bytes      {hashlib.shake_128(b'abc').hexdigest(10)}")
    print(f"guaranteed algorithms    {', '.join(sorted(hashlib.algorithms_guaranteed))}")
    print()

    a, b, short = find_collision()
    print(f"noncompliant: {a.decode()!r} and {b.decode()!r} share id {short}")
    print(f"noncompliant: ('ab','c') == ('a','bc') -> {noncompliant_key('ab', 'c') == noncompliant_key('a', 'bc')}")
    print(f"compliant:    full sha256 ids differ   -> {hashlib.sha256(a).digest() != hashlib.sha256(b).digest()}")
    print(f"compliant:    ('ab','c') == ('a','bc') -> {compliant_key('ab', 'c') == compliant_key('a', 'bc')}")


if __name__ == "__main__":
    main()

# Output:
# sha256('abc')   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
# sha3_256('abc') 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
# md5('abc')      900150983cd24fb0d6963f7d28e17f72
# incremental == one-shot: True
# file_digest(sha256)      a77aedfe2e4a7232...
# blake2b keyed, 16 bytes  dc6d0b605688006914a207de52af048d
# shake_128, 10 bytes      5881092dd818bf5cf8a3
# guaranteed algorithms    blake2b, blake2s, md5, sha1, sha224, sha256, sha384, sha3_224, sha3_256, sha3_384, sha3_512, sha512, shake_128, shake_256
#
# noncompliant: 'invoice-55994' and 'invoice-107486' share id ad613ada
# noncompliant: ('ab','c') == ('a','bc') -> True
# compliant:    full sha256 ids differ   -> True
# compliant:    ('ab','c') == ('a','bc') -> False
