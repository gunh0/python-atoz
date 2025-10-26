"""HKDF from hmac, verified against RFC 5869 — one master key, independent subkeys

https://www.rfc-editor.org/rfc/rfc5869    (CWE-323: https://cwe.mitre.org/data/definitions/323.html)

Services often have one master secret and several jobs for it: signing session
cookies, signing API tokens, encrypting a cache. Using the same key for all of
them means a value produced in one context is valid in another, so a cookie tag
can pass as an API token tag. Each purpose needs its own key.

HKDF (extract-then-expand) is the standard way to get them: extract a
pseudorandom key PRK = HMAC(salt, IKM), then expand it with a purpose label
("info") into as many bytes as needed. It is ~10 lines on top of hmac and the
RFC ships test vectors, so check them. HKDF is for high-entropy input keys;
passwords need a slow KDF (PBKDF2, scrypt) instead.
"""

import hashlib
import hmac

MASTER = bytes.fromhex("8f2c6a10d4e7b3955e0c1a7f24d8b6e3f1a09c7d5b3e2f4a6c8d0e1f2a3b4c5d")


def hkdf_extract(salt: bytes, ikm: bytes, hash_name: str = "sha256") -> bytes:
    if not salt:
        salt = bytes(hashlib.new(hash_name).digest_size)  # RFC: default is HashLen zeros
    return hmac.digest(salt, ikm, hash_name)


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str = "sha256") -> bytes:
    hash_len = hashlib.new(hash_name).digest_size
    if length > 255 * hash_len:
        raise ValueError("HKDF cannot produce more than 255 blocks")
    okm, block = b"", b""
    for counter in range(1, -(-length // hash_len) + 1):
        block = hmac.digest(prk, block + info + bytes([counter]), hash_name)
        okm += block
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int, hash_name: str = "sha256") -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm, hash_name), info, length, hash_name)


VECTORS = [  # RFC 5869 Appendix A: (case, hash, IKM, salt, info, L, PRK, OKM)
    (1, "sha256", "0b" * 22, "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
     "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
    (2, "sha256", bytes(range(0x00, 0x50)).hex(), bytes(range(0x60, 0xB0)).hex(),
     bytes(range(0xB0, 0x100)).hex(), 82,
     "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
     "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
     "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
     "cc30c58179ec3e87c14c01d5c1f3434f1d87"),
    (3, "sha256", "0b" * 22, "", "", 42,
     "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
     "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
    (4, "sha1", "0b" * 11, "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
     "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
     "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"),
    (7, "sha1", "0c" * 22, "", "", 42,
     "2adccada18779e7c2077ad2eb19d3f3e731385dd",
     "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48"),
]


def noncompliant_keys() -> dict[str, bytes]:
    return {"cookie": MASTER, "api": MASTER}


def compliant_keys() -> dict[str, bytes]:
    salt = b"example-service-v1"
    return {purpose: hkdf(MASTER, salt, f"{purpose}/hmac-sha256".encode(), 32)
            for purpose in ("cookie", "api")}


def cookie_tag_passes_as_api_token(keys: dict[str, bytes], msg: bytes) -> bool:
    cookie_tag = hmac.digest(keys["cookie"], msg, "sha256")  # what the browser holds
    api_expected = hmac.digest(keys["api"], msg, "sha256")  # what the API checks
    return hmac.compare_digest(cookie_tag, api_expected)


def main() -> None:
    for case, h, ikm, salt, info, length, prk, okm in VECTORS:
        got_prk = hkdf_extract(bytes.fromhex(salt), bytes.fromhex(ikm), h)
        got_okm = hkdf_expand(got_prk, bytes.fromhex(info), length, h)
        print(f"RFC 5869 case {case} ({h:6}): PRK {got_prk.hex() == prk}, OKM {got_okm.hex() == okm}")

    print(f"noncompliant: cookie tag accepted as API token: "
          f"{cookie_tag_passes_as_api_token(noncompliant_keys(), b'sub=alice')}")
    keys = compliant_keys()
    print(f"compliant:    cookie tag accepted as API token: "
          f"{cookie_tag_passes_as_api_token(keys, b'sub=alice')}")
    print(f"compliant:    cookie key {keys['cookie'].hex()[:16]}...  api key {keys['api'].hex()[:16]}...")
    try:
        hkdf_expand(keys["cookie"], b"", 255 * 32 + 1)
    except ValueError as exc:
        print(f"compliant:    oversize request rejected: {exc}")


if __name__ == "__main__":
    main()

# Output:
# RFC 5869 case 1 (sha256): PRK True, OKM True
# RFC 5869 case 2 (sha256): PRK True, OKM True
# RFC 5869 case 3 (sha256): PRK True, OKM True
# RFC 5869 case 4 (sha1  ): PRK True, OKM True
# RFC 5869 case 7 (sha1  ): PRK True, OKM True
# noncompliant: cookie tag accepted as API token: True
# compliant:    cookie tag accepted as API token: False
# compliant:    cookie key 3018a58e466c5104...  api key a7317b233754dc93...
# compliant:    oversize request rejected: HKDF cannot produce more than 255 blocks
