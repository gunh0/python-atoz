"""PBKDF2 checked against RFC 6070 — and why dkLen > hash length helps the attacker

https://www.rfc-editor.org/rfc/rfc6070    (CWE-916: https://cwe.mitre.org/data/definitions/916.html)

PBKDF2 output is a series of hash-sized blocks T1 || T2 || ..., and each block
costs a full run of c HMAC iterations computed independently. Asking for
40 bytes from PBKDF2-HMAC-SHA1 (20-byte blocks) doubles the defender's work,
but an attacker testing a password guess only computes T1 and compares it with
the first 20 bytes of the stored hash. The extra block is pure overhead for
you and free for them.

So: request at most one block (dklen <= digest size), spend the budget on
iterations instead, and pick the hash by your iteration budget: OWASP lists
600,000 for SHA-256 and 210,000 for SHA-512. The hand-written version below
counts HMAC calls to make the asymmetry visible, after both it and
hashlib.pbkdf2_hmac pass the RFC 6070 vectors.
"""

import hashlib
import hmac

VECTORS = [  # RFC 6070: PBKDF2-HMAC-SHA1 (password, salt, iterations, dkLen, expected)
    (b"password", b"salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
    (b"password", b"salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
    (b"password", b"salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"),
    # (b"password", b"salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984")
    # is skipped: it takes seconds even in C.
    (b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
     "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
    (b"pass\x00word", b"sa\x00lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"),
]


class CountingPBKDF2:
    def __init__(self, hash_name: str = "sha1") -> None:
        self.hash_name, self.hmac_calls = hash_name, 0

    def _prf(self, key: bytes, msg: bytes) -> bytes:
        self.hmac_calls += 1
        return hmac.digest(key, msg, self.hash_name)

    def block(self, password: bytes, salt: bytes, iterations: int, index: int) -> bytes:
        u = self._prf(password, salt + index.to_bytes(4, "big"))
        acc = int.from_bytes(u)
        for _ in range(iterations - 1):
            u = self._prf(password, u)
            acc ^= int.from_bytes(u)
        return acc.to_bytes(len(u))

    def derive(self, password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
        h_len = hashlib.new(self.hash_name).digest_size
        blocks = -(-dklen // h_len)
        return b"".join(self.block(password, salt, iterations, i) for i in range(1, blocks + 1))[:dklen]


def main() -> None:
    for password, salt, c, dklen, want in VECTORS:
        std = hashlib.pbkdf2_hmac("sha1", password, salt, c, dklen).hex() == want
        own = CountingPBKDF2().derive(password, salt, c, dklen).hex() == want
        print(f"RFC 6070 c={c:<5} dkLen={dklen}: hashlib {std}, hand-written {own}")

    c = 10_000  # small so the pure-Python counter stays fast; production uses 600,000+
    stored_salt, real_password = b"per-user-salt-16", b"Summer2024!"
    defender = CountingPBKDF2()
    stored = defender.derive(real_password, stored_salt, c, 40)  # two SHA-1 blocks
    print(f"noncompliant: dkLen=40, defender spends {defender.hmac_calls} HMAC calls per login")
    for guess in (b"123456", b"password", b"Summer2024!"):
        attacker = CountingPBKDF2()
        if hmac.compare_digest(attacker.block(guess, stored_salt, c, 1), stored[:20]):
            print(f"noncompliant: attacker confirms {guess.decode()!r} using only "
                  f"{attacker.hmac_calls} HMAC calls per guess")

    defender = CountingPBKDF2("sha256")
    defender.derive(real_password, stored_salt, c * 2, 32)  # one block, double iterations
    print(f"compliant:    dkLen=32 sha256, {defender.hmac_calls} HMAC calls per login, "
          f"attacker needs the same {defender.hmac_calls} per guess")


if __name__ == "__main__":
    main()

# Output:
# RFC 6070 c=1     dkLen=20: hashlib True, hand-written True
# RFC 6070 c=2     dkLen=20: hashlib True, hand-written True
# RFC 6070 c=4096  dkLen=20: hashlib True, hand-written True
# RFC 6070 c=4096  dkLen=25: hashlib True, hand-written True
# RFC 6070 c=4096  dkLen=16: hashlib True, hand-written True
# noncompliant: dkLen=40, defender spends 20000 HMAC calls per login
# noncompliant: attacker confirms 'Summer2024!' using only 10000 HMAC calls per guess
# compliant:    dkLen=32 sha256, 20000 HMAC calls per login, attacker needs the same 20000 per guess
