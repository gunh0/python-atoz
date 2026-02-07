"""CWE-347: JWT validation — claims, `alg: none`, and RS256/HS256 algorithm confusion

https://cwe.mitre.org/data/definitions/347.html    (RFC 7519: https://www.rfc-editor.org/rfc/rfc7519)

An HS256 JWT is base64url(header).base64url(payload).base64url(HMAC-SHA256).
The signature only says "our key signed this at some point". Whether the token
is valid *now* and *for this service* lives in the claims: exp, nbf, aud, iss.
The compliant verifier checks all of them against an injected clock.

v2: the header is attacker-controlled, so it must never choose the algorithm.
A verifier that dispatches on header["alg"] accepts `"alg": "none"` with an
empty signature, and, handed an RSA public key for RS256, it will happily
verify an HS256 token whose HMAC key *is that public key* — which the attacker
can download. The fix is to pin the algorithm to the key in configuration and
reject any header that disagrees. (The RSA key is generated deterministically
and is far too small for real use; it only makes RS256 runnable here.)
"""

import base64
import hashlib
import hmac
import json

KEY = b"0123456789abcdef0123456789abcdef"  # 256-bit HS256 key (fixture)
NOW = 1_750_000_000  # fixed clock: 2025-06-15T15:06:40Z
LEEWAY = 30


class InvalidToken(Exception):
    pass


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- a tiny, deterministic RS256 so the confusion attack is real -------------------

def _is_probable_prime(n: int) -> bool:
    if n % 2 == 0:
        return n == 2
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime_from(label: bytes) -> int:
    n = int.from_bytes(hashlib.sha512(label).digest()) | (1 << 511) | 1
    while not _is_probable_prime(n):
        n += 2
    return n


P, Q, E = _prime_from(b"idp-p"), _prime_from(b"idp-q"), 65537
N, D = P * Q, pow(E, -1, (P - 1) * (Q - 1))
PUBLIC_JWK = json.dumps({"kty": "RSA", "n": b64url(N.to_bytes(128)), "e": "AQAB"}).encode()
SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _emsa_pkcs1(msg: bytes) -> bytes:
    t = SHA256_DIGESTINFO + hashlib.sha256(msg).digest()
    return b"\x00\x01" + b"\xff" * (128 - len(t) - 3) + b"\x00" + t


def rs256_sign(msg: bytes) -> bytes:
    return pow(int.from_bytes(_emsa_pkcs1(msg)), D, N).to_bytes(128)


def rs256_verify(msg: bytes, sig: bytes) -> bool:
    return pow(int.from_bytes(sig), E, N).to_bytes(128) == _emsa_pkcs1(msg)


# --- encoding -----------------------------------------------------------------------

def encode(claims: dict, alg: str = "HS256", key: bytes = KEY) -> str:
    header = {"alg": alg, "typ": "JWT"}
    signing_input = ".".join(b64url(json.dumps(part, separators=(",", ":")).encode())
                             for part in (header, claims)).encode()
    if alg == "HS256":
        sig = hmac.digest(key, signing_input, "sha256")
    elif alg == "RS256":
        sig = rs256_sign(signing_input)
    else:  # "none"
        sig = b""
    return f"{signing_input.decode()}.{b64url(sig)}"


def _split(token: str) -> tuple[dict, dict, bytes, bytes]:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        return (json.loads(unb64url(header_b64)), json.loads(unb64url(payload_b64)),
                f"{header_b64}.{payload_b64}".encode(), unb64url(sig_b64))
    except (ValueError, TypeError) as exc:  # bad base64 / json / shape
        raise InvalidToken("malformed token") from exc


# --- verifiers ----------------------------------------------------------------------

def noncompliant_verify(token: str, audience: str, now: int) -> dict:
    """v1 bug: the signature is checked, the claims are not."""
    header, claims, signing_input, sig = _split(token)
    if header.get("alg") != "HS256" or not hmac.compare_digest(
            hmac.digest(KEY, signing_input, "sha256"), sig):
        raise InvalidToken("bad signature")
    return claims


def noncompliant_verify_any(token: str, key: bytes) -> dict:
    """v2 bug: the token's own header picks the algorithm used to check it."""
    header, claims, signing_input, sig = _split(token)
    alg = header.get("alg")
    if alg == "none":
        return claims
    if alg == "HS256" and hmac.compare_digest(hmac.digest(key, signing_input, "sha256"), sig):
        return claims
    if alg == "RS256" and rs256_verify(signing_input, sig):
        return claims
    raise InvalidToken("bad signature")


TRUSTED_KEYS = {  # issuer -> (the one algorithm allowed, key material)
    "https://idp.example": ("HS256", KEY),
    "https://sso.example": ("RS256", PUBLIC_JWK),
}


def compliant_verify(token: str, audience: str, now: int) -> dict:
    header, claims, signing_input, sig = _split(token)
    if claims.get("iss") not in TRUSTED_KEYS:
        raise InvalidToken("unknown issuer")
    alg, key = TRUSTED_KEYS[claims["iss"]]
    if header.get("alg") != alg:  # configuration decides, the header must agree
        raise InvalidToken(f"alg {header.get('alg')!r} not allowed for this issuer")
    ok = (hmac.compare_digest(hmac.digest(key, signing_input, "sha256"), sig) if alg == "HS256"
          else rs256_verify(signing_input, sig))
    if not ok:
        raise InvalidToken("bad signature")
    for name in ("exp", "aud"):
        if name not in claims:
            raise InvalidToken(f"missing {name}")
    if not isinstance(claims["exp"], int) or now >= claims["exp"] + LEEWAY:
        raise InvalidToken("expired")
    if "nbf" in claims and now < claims["nbf"] - LEEWAY:
        raise InvalidToken("not yet valid")
    aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    if audience not in aud:
        raise InvalidToken("wrong audience")
    return claims


def swap_payload(token: str, claims: dict) -> str:
    """Attacker edits the payload and keeps the original signature."""
    header_b64, _, sig_b64 = token.split(".")
    return f"{header_b64}.{b64url(json.dumps(claims, separators=(',', ':')).encode())}.{sig_b64}"


def run(label: str, verify, tokens: dict[str, str]) -> None:
    for name, token in tokens.items():
        try:
            result = f"accepted sub={verify(token)['sub']}"
        except InvalidToken as exc:
            result = f"rejected ({exc})"
        print(f"{label + ':':13} {name:15} {result}")


def main() -> None:
    base = {"sub": "alice", "iss": "https://idp.example", "aud": "admin-api",
            "iat": NOW - 60, "exp": NOW + 600}
    good = encode(base)
    claim_tokens = {
        "valid": good,
        "expired": encode({**base, "exp": NOW - 3600}),
        "within leeway": encode({**base, "exp": NOW - 10}),
        "not yet valid": encode({**base, "nbf": NOW + 3600}),
        "other audience": encode({**base, "aud": "billing-api"}),
        "multi audience": encode({**base, "aud": ["billing-api", "admin-api"]}),
        "no exp claim": encode({k: v for k, v in base.items() if k != "exp"}),
        "payload edited": swap_payload(good, {**base, "sub": "root"}),
        "garbage": "not.a.jwt",
    }
    run("noncompliant", lambda t: noncompliant_verify(t, "admin-api", NOW), claim_tokens)
    run("compliant", lambda t: compliant_verify(t, "admin-api", NOW), claim_tokens)
    print()

    sso = {**base, "iss": "https://sso.example"}
    root = {**sso, "sub": "root"}
    alg_tokens = {
        "RS256 from sso": encode(sso, "RS256"),
        "alg none": encode(root, "none"),
        "HS256 w/ pubkey": encode(root, "HS256", key=PUBLIC_JWK),  # attacker knows the JWK
        "RS256 tampered": swap_payload(encode(sso, "RS256"), root),
    }
    print(f"public key published as JWK: {len(PUBLIC_JWK)} bytes, n is {N.bit_length()} bits")
    run("noncompliant", lambda t: noncompliant_verify_any(t, key=PUBLIC_JWK), alg_tokens)
    run("compliant", lambda t: compliant_verify(t, "admin-api", NOW), alg_tokens)


if __name__ == "__main__":
    main()

# Output:
# noncompliant: valid           accepted sub=alice
# noncompliant: expired         accepted sub=alice
# noncompliant: within leeway   accepted sub=alice
# noncompliant: not yet valid   accepted sub=alice
# noncompliant: other audience  accepted sub=alice
# noncompliant: multi audience  accepted sub=alice
# noncompliant: no exp claim    accepted sub=alice
# noncompliant: payload edited  rejected (bad signature)
# noncompliant: garbage         rejected (malformed token)
# compliant:    valid           accepted sub=alice
# compliant:    expired         rejected (expired)
# compliant:    within leeway   accepted sub=alice
# compliant:    not yet valid   rejected (not yet valid)
# compliant:    other audience  rejected (wrong audience)
# compliant:    multi audience  accepted sub=alice
# compliant:    no exp claim    rejected (missing exp)
# compliant:    payload edited  rejected (bad signature)
# compliant:    garbage         rejected (malformed token)
#
# public key published as JWK: 207 bytes, n is 1023 bits
# noncompliant: RS256 from sso  accepted sub=alice
# noncompliant: alg none        accepted sub=root
# noncompliant: HS256 w/ pubkey accepted sub=root
# noncompliant: RS256 tampered  rejected (bad signature)
# compliant:    RS256 from sso  accepted sub=alice
# compliant:    alg none        rejected (alg 'none' not allowed for this issuer)
# compliant:    HS256 w/ pubkey rejected (alg 'HS256' not allowed for this issuer)
# compliant:    RS256 tampered  rejected (bad signature)
