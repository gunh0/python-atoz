"""CWE-261/CWE-327: base64 and XOR are not encryption

https://cwe.mitre.org/data/definitions/261.html    (CWE-327: https://cwe.mitre.org/data/definitions/327.html)

"The password in the config is encrypted" often means base64, which is an
encoding with no key at all. One step up is XOR with a short repeating key:
every structured format has a known prefix ({"user": ..., <?xml, PK\\x03\\x04),
and XOR of ciphertext with known plaintext *is* the key. Reusing a keystream
for two messages cancels it out entirely. And even a perfect one-time XOR pad
does nothing for integrity: flipping a ciphertext bit flips the same plaintext
bit, so "amount=100" becomes "amount=900" without knowing the key.

The standard library has no block cipher on purpose. For confidentiality use
a vetted AEAD (AES-GCM or ChaCha20-Poly1305 from the `cryptography` package)
or keep the secret out of the file entirely; for integrity, which is the part
the stdlib does cover, use HMAC and verify before trusting anything.
"""

import base64
import hashlib
import hmac
import json
import secrets
from itertools import cycle

XOR_KEY = b"Nb7#q"  # what the "encryption" helper hard-codes
MAC_KEY = bytes.fromhex("c0ffee00" * 8)


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ k for b, k in zip(data, cycle(key)))


def recover_repeating_key(ciphertext: bytes, known_prefix: bytes, max_len: int = 8) -> bytes:
    """Try each key length; keep the one whose key decrypts the whole thing to valid JSON."""
    for length in range(1, max_len + 1):
        key = xor(ciphertext[:length], known_prefix[:length])
        try:
            json.loads(xor(ciphertext, key))
            return key
        except ValueError:
            continue
    raise ValueError("no key found")


def main() -> None:
    stored = "UzNjcjN0IXB3"  # config.ini: db_password_encrypted = UzNjcjN0IXB3
    print(f"noncompliant: base64 'encrypted' value decodes to {base64.b64decode(stored).decode()!r}")

    record = b'{"user": "alice", "role": "admin", "api_token": "tok_51fe8a29c0"}'
    ciphertext = xor(record, XOR_KEY)
    key = recover_repeating_key(ciphertext, b'{"user": "')
    print(f"noncompliant: XOR key recovered from known JSON prefix: {key!r}")
    print(f"noncompliant: plaintext {xor(ciphertext, key).decode()}")

    pad = secrets.token_bytes(64)  # a truly random pad, but used twice
    c1, c2 = xor(b"transfer amount=100 to=bob", pad), xor(b"transfer amount=250 to=eve", pad)
    leaked = xor(xor(c1, c2), b"transfer amount=100 to=bob")
    print(f"noncompliant: keystream reused, second message: {leaked.decode()!r}")

    order, pad = b"amount=100;to=bob", secrets.token_bytes(17)  # fresh one-time pad, used once
    c = bytearray(xor(order, pad))
    c[7] ^= ord("1") ^ ord("9")  # attacker flips bits without knowing the pad
    print(f"noncompliant: bit-flipped ciphertext decrypts to {xor(bytes(c), pad).decode()!r}")

    tag = hmac.new(MAC_KEY, xor(order, pad), hashlib.sha256).digest()
    for label, blob in (("original", xor(order, pad)), ("bit-flipped", bytes(c))):
        ok = hmac.compare_digest(tag, hmac.new(MAC_KEY, blob, hashlib.sha256).digest())
        print(f"compliant:    HMAC over ciphertext, {label:11} -> {'accepted' if ok else 'rejected'}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: base64 'encrypted' value decodes to 'S3cr3t!pw'
# noncompliant: XOR key recovered from known JSON prefix: b'Nb7#q'
# noncompliant: plaintext {"user": "alice", "role": "admin", "api_token": "tok_51fe8a29c0"}
# noncompliant: keystream reused, second message: 'transfer amount=250 to=eve'
# noncompliant: bit-flipped ciphertext decrypts to 'amount=900;to=bob'
# compliant:    HMAC over ciphertext, original    -> accepted
# compliant:    HMAC over ciphertext, bit-flipped -> rejected
