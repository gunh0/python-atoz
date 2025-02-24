"""CWE-916: password hashing — scrypt/PBKDF2 with per-user salt and parameter strings

https://cwe.mitre.org/data/definitions/916.html

A fast unsalted hash (sha256(password)) turns a leaked user table into a lookup
exercise: equal passwords give equal hashes, and a precomputed table of common
passwords cracks them all at once. A password hash must be slow on purpose,
salted per user, and self-describing.

The stored string below follows the PHC style ($id$params$salt$hash), so the
algorithm and cost travel with each hash. That is what makes it possible to
raise the cost later without a flag day. Parameters follow the OWASP Password
Storage Cheat Sheet: scrypt N=2**17, r=8, p=1, or PBKDF2-HMAC-SHA256 with
600,000 iterations where scrypt is not available.
"""

import base64
import hashlib
import hmac
import secrets

SCRYPT = {"ln": 17, "r": 8, "p": 1}  # N = 2**ln; memory = 128 * r * N = 128 MiB
PBKDF2_ITERATIONS = 600_000


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode().rstrip("=")


def unb64(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def noncompliant_hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _scrypt(password: str, salt: bytes, ln: int, r: int, p: int) -> bytes:
    n = 2**ln
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p,
                          maxmem=256 * r * n, dklen=32)


def hash_password(password: str, salt: bytes | None = None, scheme: str = "scrypt") -> str:
    salt = salt if salt is not None else secrets.token_bytes(16)
    if scheme == "scrypt":
        digest = _scrypt(password, salt, **SCRYPT)
        params = ",".join(f"{k}={v}" for k, v in SCRYPT.items())
        return f"$scrypt${params}${b64(salt)}${b64(digest)}"
    if scheme == "pbkdf2-sha256":
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
        return f"$pbkdf2-sha256$i={PBKDF2_ITERATIONS}${b64(salt)}${b64(digest)}"
    raise ValueError(f"unknown scheme {scheme!r}")


def verify_password(password: str, stored: str) -> bool:
    _, scheme, params, salt_b64, hash_b64 = stored.split("$")
    opts = {k: int(v) for k, v in (kv.split("=") for kv in params.split(","))}
    salt, expected = unb64(salt_b64), unb64(hash_b64)
    if scheme == "scrypt":
        actual = _scrypt(password, salt, **opts)
    elif scheme == "pbkdf2-sha256":
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, opts["i"])
    else:
        raise ValueError(f"unknown scheme {scheme!r}")
    return hmac.compare_digest(actual, expected)


def main() -> None:
    common = ["123456", "password", "qwerty", "Summer2024!", "letmein"]
    table = {noncompliant_hash(pw): pw for pw in common}  # built once, reused forever
    leaked = {"alice": noncompliant_hash("Summer2024!"), "bob": noncompliant_hash("Summer2024!")}
    print(f"noncompliant: alice == bob hash  {leaked['alice'] == leaked['bob']}")
    for user, h in leaked.items():
        print(f"noncompliant: {user:5} cracked by lookup -> {table.get(h)}")

    # Fixed salts only to keep the Output block reproducible; production omits salt=.
    alice = hash_password("Summer2024!", salt=bytes.fromhex("a1" * 16))
    bob = hash_password("Summer2024!", salt=bytes.fromhex("b0" * 16))
    legacy = hash_password("Summer2024!", salt=bytes.fromhex("c3" * 16), scheme="pbkdf2-sha256")
    print(f"compliant:    alice {alice}")
    print(f"compliant:    bob   {bob}")
    print(f"compliant:    carol {legacy}")
    print(f"compliant:    alice == bob hash  {alice == bob}")
    print(f"compliant:    verify alice good  {verify_password('Summer2024!', alice)}")
    print(f"compliant:    verify alice bad   {verify_password('summer2024!', alice)}")
    print(f"compliant:    verify carol good  {verify_password('Summer2024!', legacy)}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: alice == bob hash  True
# noncompliant: alice cracked by lookup -> Summer2024!
# noncompliant: bob   cracked by lookup -> Summer2024!
# compliant:    alice $scrypt$ln=17,r=8,p=1$oaGhoaGhoaGhoaGhoaGhoQ$qW6g+EKYmnMWVvwNjwgHrwJorj0R9qHByxQzbYgaec8
# compliant:    bob   $scrypt$ln=17,r=8,p=1$sLCwsLCwsLCwsLCwsLCwsA$d8zA0H18SyPkYve3wvCCGrYjPdIhEmGjKY6gGN70FIo
# compliant:    carol $pbkdf2-sha256$i=600000$w8PDw8PDw8PDw8PDw8PDww$j0u6cBYqTNDotlwbKLnBmf2YHynWDXe1GIHn6sezjrs
# compliant:    alice == bob hash  False
# compliant:    verify alice good  True
# compliant:    verify alice bad   False
# compliant:    verify carol good  True
