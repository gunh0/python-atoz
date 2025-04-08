"""HMAC-SHA-256/512 checked against the RFC 4231 test vectors

https://www.rfc-editor.org/rfc/rfc4231    (CWE-327: https://cwe.mitre.org/data/definitions/327.html)

HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m)), where K' is the key padded
to the hash block size, or *hashed first* if it is longer than one block. The
construction is short enough that people re-implement it (in another language,
in a hardware token, in a database function) and get one detail wrong.

Known-answer tests are how you catch that. The hand-rolled version below
forgets the long-key rule: it agrees with the RFC on short keys and silently
produces different MACs for keys over 64 bytes (test cases 6 and 7). In
Python, use hmac.new / hmac.digest; when you must port HMAC, keep these
vectors in the port's test suite.
"""

import hashlib
import hmac

CASES = [  # (case, key, data, sha256 hex, sha512 hex or None, truncate_bytes)
    (1, b"\x0b" * 20, b"Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
     "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
     "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", None),
    (2, b"Jefe", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
     "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
     "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", None),
    (3, b"\xaa" * 20, b"\xdd" * 50,
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", None, None),
    (4, bytes(range(1, 26)), b"\xcd" * 50,
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", None, None),
    (5, b"\x0c" * 20, b"Test With Truncation",
     "a3b6167473100ee06e0c796c2955552b", None, 16),
    (6, b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", None, None),
    (7, b"\xaa" * 131,
     b"This is a test using a larger than block-size key and a larger than block-size data."
     b" The key needs to be hashed before being used by the HMAC algorithm.",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", None, None),
]


def _hmac(key: bytes, msg: bytes, hash_long_keys: bool) -> bytes:
    block = 64  # SHA-256 block size in bytes
    if hash_long_keys and len(key) > block:
        key = hashlib.sha256(key).digest()
    key = key[:block].ljust(block, b"\x00")
    inner = hashlib.sha256(bytes(b ^ 0x36 for b in key) + msg).digest()
    return hashlib.sha256(bytes(b ^ 0x5C for b in key) + inner).digest()


def noncompliant_hmac(key: bytes, msg: bytes) -> bytes:
    return _hmac(key, msg, hash_long_keys=False)  # truncates long keys instead


def compliant_hmac(key: bytes, msg: bytes) -> bytes:
    return _hmac(key, msg, hash_long_keys=True)


def main() -> None:
    print("case  stdlib-256  stdlib-512  hand-rolled  fixed")
    for case, key, data, want256, want512, trunc in CASES:
        n = trunc or 32
        std256 = hmac.new(key, data, hashlib.sha256).hexdigest()[: n * 2] == want256
        std512 = "-" if want512 is None else hmac.digest(key, data, "sha512").hex() == want512
        bad = noncompliant_hmac(key, data)[:n].hex() == want256
        good = compliant_hmac(key, data)[:n].hex() == want256
        print(f"{case:>4}  {std256!s:10}  {std512!s:10}  {bad!s:11}  {good}")

    # A keyed HMAC object can be copied to reuse the absorbed key for many messages.
    base = hmac.new(b"Jefe", digestmod="sha256")
    tagged = base.copy()
    tagged.update(b"what do ya want for nothing?")
    print(f"copy() reuse matches case 2: {tagged.hexdigest() == CASES[1][3]}")


if __name__ == "__main__":
    main()

# Output:
# case  stdlib-256  stdlib-512  hand-rolled  fixed
#    1  True        True        True         True
#    2  True        True        True         True
#    3  True        -           True         True
#    4  True        -           True         True
#    5  True        -           True         True
#    6  True        -           False        True
#    7  True        -           False        True
# copy() reuse matches case 2: True
