"""CWE-916: password hashing — salted scrypt/PBKDF2 strings and upgrade-on-login rehash

https://cwe.mitre.org/data/definitions/916.html

A fast unsalted hash (sha256(password)) turns a leaked user table into a lookup
exercise: equal passwords give equal hashes, and a precomputed table of common
passwords cracks them all at once. A password hash must be slow on purpose,
salted per user, and self-describing.

The stored string follows the PHC style ($id$params$salt$hash), so the
algorithm and cost travel with each hash. Parameters follow the OWASP Password
Storage Cheat Sheet: scrypt N=2**17, r=8, p=1, or PBKDF2-HMAC-SHA256 with
600,000 iterations where scrypt is not available.

v2: costs only go up, and the plaintext is only available at login. So on a
*successful* login, check the stored parameters against today's policy and
rehash if they are weaker. The order matters: an "upgrade first, verify
second" login stores the attacker's guess as the new hash and lets them in.
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


def hash_password(password: str, salt: bytes | None = None, scheme: str = "scrypt",
                  params: dict[str, int] | None = None) -> str:
    salt = salt if salt is not None else secrets.token_bytes(16)
    if scheme == "scrypt":
        opts = params or SCRYPT
        digest = _scrypt(password, salt, **opts)
    elif scheme == "pbkdf2-sha256":
        opts = params or {"i": PBKDF2_ITERATIONS}
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, opts["i"])
    else:
        raise ValueError(f"unknown scheme {scheme!r}")
    encoded = ",".join(f"{k}={v}" for k, v in opts.items())
    return f"${scheme}${encoded}${b64(salt)}${b64(digest)}"


def _parse(stored: str) -> tuple[str, dict[str, int], bytes, bytes]:
    _, scheme, params, salt_b64, hash_b64 = stored.split("$")
    opts = {k: int(v) for k, v in (kv.split("=") for kv in params.split(","))}
    return scheme, opts, unb64(salt_b64), unb64(hash_b64)


def verify_password(password: str, stored: str) -> bool:
    scheme, opts, salt, expected = _parse(stored)
    if scheme == "scrypt":
        actual = _scrypt(password, salt, **opts)
    elif scheme == "pbkdf2-sha256":
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, opts["i"])
    else:
        raise ValueError(f"unknown scheme {scheme!r}")
    return hmac.compare_digest(actual, expected)


def needs_rehash(stored: str) -> bool:
    scheme, opts, _, _ = _parse(stored)
    return scheme != "scrypt" or any(opts.get(k, 0) < v for k, v in SCRYPT.items())


def noncompliant_login(db: dict[str, str], user: str, password: str) -> bool:
    if needs_rehash(db[user]):
        db[user] = hash_password(password, salt=b"\x00" * 16)  # upgrade first ...
    return verify_password(password, db[user])  # ... then verify the hash just written


def compliant_login(db: dict[str, str], user: str, password: str, salt: bytes) -> str:
    if not verify_password(password, db[user]):
        return "denied"
    if needs_rehash(db[user]):
        db[user] = hash_password(password, salt=salt)  # production: salt omitted
        return "ok, rehashed"
    return "ok"


def short(stored: str) -> str:
    return stored.rsplit("$", 2)[0] + "$..."


def main() -> None:
    common = ["123456", "password", "qwerty", "Summer2024!", "letmein"]
    table = {noncompliant_hash(pw): pw for pw in common}
    print(f"noncompliant: unsalted sha256 cracked by lookup -> {table[noncompliant_hash('Summer2024!')]}")

    # A user table that has lived through two policy changes. Fixed salts keep
    # the Output block reproducible; production code never passes salt=.
    db = {
        "alice": hash_password("Summer2024!", bytes.fromhex("a1" * 16), "pbkdf2-sha256", {"i": 100_000}),
        "bob": hash_password("correct horse", bytes.fromhex("b0" * 16), "scrypt", {"ln": 14, "r": 8, "p": 1}),
    }
    for user, stored in db.items():
        print(f"stored        {user:5} {short(stored)}  needs_rehash={needs_rehash(stored)}")

    stolen = dict(db)
    print(f"noncompliant: attacker logs in as alice with a guess -> {noncompliant_login(stolen, 'alice', 'hunter2')}")
    print(f"noncompliant: alice's real password still works     -> {verify_password('Summer2024!', stolen['alice'])}")

    attempts = [("alice", "hunter2"), ("alice", "Summer2024!"), ("bob", "correct horse"), ("alice", "Summer2024!")]
    for i, (user, password) in enumerate(attempts):
        result = compliant_login(db, user, password, salt=bytes([0x10 + i]) * 16)
        print(f"compliant:    login {user:5} {password!r:15} -> {result:13} {short(db[user])}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: unsalted sha256 cracked by lookup -> Summer2024!
# stored        alice $pbkdf2-sha256$i=100000$...  needs_rehash=True
# stored        bob   $scrypt$ln=14,r=8,p=1$...  needs_rehash=True
# noncompliant: attacker logs in as alice with a guess -> True
# noncompliant: alice's real password still works     -> False
# compliant:    login alice 'hunter2'       -> denied        $pbkdf2-sha256$i=100000$...
# compliant:    login alice 'Summer2024!'   -> ok, rehashed  $scrypt$ln=17,r=8,p=1$...
# compliant:    login bob   'correct horse' -> ok, rehashed  $scrypt$ln=17,r=8,p=1$...
# compliant:    login alice 'Summer2024!'   -> ok            $scrypt$ln=17,r=8,p=1$...
