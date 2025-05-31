"""CWE-347: JWT validation — a signature check alone is not enough

https://cwe.mitre.org/data/definitions/347.html    (RFC 7519: https://www.rfc-editor.org/rfc/rfc7519)

An HS256 JWT is base64url(header).base64url(payload).base64url(HMAC-SHA256).
The signature only says "our key signed this at some point". Whether the token
is valid *now* and *for this service* lives in the claims: exp (expiry), nbf
(not before), aud (intended audience), iss (issuer). A verifier that checks the
signature and stops accepts expired tokens, tokens minted for later, and tokens
issued for another service that shares the signing key.

The compliant verifier checks the signature in constant time, then every
claim against an injected clock with a small leeway for clock skew. The clock
is a parameter, which also makes the checks testable.
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


def encode(claims: dict, key: bytes = KEY) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = ".".join(b64url(json.dumps(part, separators=(",", ":")).encode())
                             for part in (header, claims))
    sig = hmac.digest(key, signing_input.encode(), "sha256")
    return f"{signing_input}.{b64url(sig)}"


def _verify_signature(token: str, key: bytes) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(unb64url(header_b64))
        expected = hmac.digest(key, f"{header_b64}.{payload_b64}".encode(), "sha256")
        if header.get("alg") != "HS256" or not hmac.compare_digest(expected, unb64url(sig_b64)):
            raise InvalidToken("bad signature")
        return json.loads(unb64url(payload_b64))
    except (ValueError, TypeError) as exc:  # bad base64 / json / shape
        raise InvalidToken("malformed token") from exc


def noncompliant_verify(token: str, audience: str, now: int) -> dict:
    return _verify_signature(token, KEY)  # "it's signed, so it's fine"


def compliant_verify(token: str, audience: str, now: int, issuer: str = "https://idp.example") -> dict:
    claims = _verify_signature(token, KEY)
    for name in ("exp", "iss", "aud"):
        if name not in claims:
            raise InvalidToken(f"missing {name}")
    if not isinstance(claims["exp"], int) or now >= claims["exp"] + LEEWAY:
        raise InvalidToken("expired")
    if "nbf" in claims and now < claims["nbf"] - LEEWAY:
        raise InvalidToken("not yet valid")
    if claims["iss"] != issuer:
        raise InvalidToken("wrong issuer")
    aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    if audience not in aud:
        raise InvalidToken("wrong audience")
    return claims


def main() -> None:
    base = {"sub": "alice", "iss": "https://idp.example", "aud": "admin-api",
            "iat": NOW - 60, "exp": NOW + 600}
    good = encode(base)
    header_b64, _, sig_b64 = good.split(".")
    forged = b64url(json.dumps({**base, "sub": "root"}, separators=(",", ":")).encode())
    tokens = {
        "valid": good,
        "expired": encode({**base, "exp": NOW - 3600}),
        "within leeway": encode({**base, "exp": NOW - 10}),
        "not yet valid": encode({**base, "nbf": NOW + 3600}),
        "other audience": encode({**base, "aud": "billing-api"}),
        "multi audience": encode({**base, "aud": ["billing-api", "admin-api"]}),
        "no exp claim": encode({k: v for k, v in base.items() if k != "exp"}),
        "payload edited": f"{header_b64}.{forged}.{sig_b64}",
        "garbage": "not.a.jwt",
    }
    print(f"token: {good}")
    for label, verify in (("noncompliant", noncompliant_verify), ("compliant", compliant_verify)):
        for name, token in tokens.items():
            try:
                claims = verify(token, audience="admin-api", now=NOW)
                result = f"accepted sub={claims['sub']}"
            except InvalidToken as exc:
                result = f"rejected ({exc})"
            print(f"{label + ':':13} {name:15} {result}")


if __name__ == "__main__":
    main()

# Output:
# token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vaWRwLmV4YW1wbGUiLCJhdWQiOiJhZG1pbi1hcGkiLCJpYXQiOjE3NDk5OTk5NDAsImV4cCI6MTc1MDAwMDYwMH0.eeFkd09l2KPtsMMatyiUaaL0PLYF3ja9hScrYAgzLEk
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
