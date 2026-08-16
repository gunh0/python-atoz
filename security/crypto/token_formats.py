"""Token formats — prefixed, checksummed API tokens that secret scanners can find

https://cwe.mitre.org/data/definitions/798.html    (cf. GitHub's token format change, 2021)

A token that is 32 random hex characters is secure, but nobody can tell it
apart from a git commit id or a sha256 checksum. When it leaks into a log or
a repository, scanners either flag every hex string or miss it.

A better format costs nothing: a fixed prefix naming the issuer and type
(acme_pat_ for a personal access token), 176 random bits in base62, and
a CRC32 checksum. Scanners match the prefix and validate the checksum offline,
so lookalikes and doc placeholders are not reported; revocation and support
can route by prefix. The checksum is for detection only, not authenticity:
the server still looks up sha256(token) in its own table.
"""

import hashlib
import re
import secrets
import string
import zlib

BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
PREFIX = "acme_pat_"
TOKEN_RE = re.compile(r"\bacme_pat_([0-9A-Za-z]{30})([0-9A-Za-z]{6})\b")


def base62(n: int, width: int) -> str:
    out = []
    for _ in range(width):
        n, r = divmod(n, 62)
        out.append(BASE62[r])
    if n:
        raise ValueError("value does not fit")
    return "".join(reversed(out))


def make_token(raw: bytes | None = None) -> str:
    raw = raw if raw is not None else secrets.token_bytes(22)  # 176 bits
    body = base62(int.from_bytes(raw), 30)
    return f"{PREFIX}{body}{base62(zlib.crc32(body.encode()), 6)}"


def checksum_ok(body: str, check: str) -> bool:
    return base62(zlib.crc32(body.encode()), 6) == check


def noncompliant_scan(text: str) -> list[str]:
    return re.findall(r"\b[0-9a-f]{32,64}\b", text)


def compliant_scan(text: str) -> list[str]:
    return [m[0] for m in TOKEN_RE.finditer(text) if checksum_ok(m[1], m[2])]


def main() -> None:
    hex_token = "4f9c2a7e1b8d3c6f0a5e9d2b7c4f1a8e"  # old-style token that leaked
    new_token = make_token(bytes.fromhex("8d2e" * 11))  # fixed bytes for a stable Output block
    lookalike = new_token[:-1] + ("A" if new_token[-1] != "A" else "B")
    corpus = "\n".join([
        "commit 3f2c1a9d8e7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a",
        "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt",
        f"curl -H 'Authorization: token {hex_token}' https://api.acme.example/user",
        f"export ACME_TOKEN={new_token}",
        f"docs example: {lookalike}",
        "docs example: acme_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ])

    hits = noncompliant_scan(corpus)
    print(f"noncompliant: {len(hits)} hex matches, of which real tokens: {sum(h == hex_token for h in hits)}")
    hits = compliant_scan(corpus)
    print(f"compliant:    {len(hits)} match, is the leaked token: {hits == [new_token]}")
    print(f"compliant:    token  {new_token}")
    print(f"compliant:    length {len(new_token)}, entropy {22 * 8} bits, "
          f"prefix tells type: {new_token.startswith(PREFIX)}")
    print(f"compliant:    stored server-side as sha256: {hashlib.sha256(new_token.encode()).hexdigest()[:16]}...")
    fresh = make_token()
    print(f"compliant:    a fresh random token passes its own checksum: "
          f"{bool(TOKEN_RE.fullmatch(fresh)) and compliant_scan(fresh) == [fresh]}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: 3 hex matches, of which real tokens: 1
# compliant:    1 match, is the leaked token: True
# compliant:    token  acme_pat_5XRH9jirp0Kfx90B43effC1uUbY7Kw3SgFf1
# compliant:    length 45, entropy 176 bits, prefix tells type: True
# compliant:    stored server-side as sha256: fd466312251b2810...
# compliant:    a fresh random token passes its own checksum: True
