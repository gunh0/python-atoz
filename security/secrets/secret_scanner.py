"""CWE-798: hard-coded credentials — a secret scanner with regex rules and entropy

https://cwe.mitre.org/data/definitions/798.html

A scanner nobody trusts gets disabled. `grep -i 'password\\|token\\|key'` flags
every settings constant and docstring and still misses a bearer token pasted
into a shell script. Useful scanners combine two signals: provider rules for
formats that are unambiguous (AWS key ids, private key blocks, credentials in
URLs), and for generic assignments a value that is long and *random-looking*,
measured as Shannon entropy per character.

v2 is about keeping the noise near zero so the scanner can gate CI:
checksummed token formats (acme_pat_..., see crypto/token_formats.py) are
only reported when the checksum validates, published test values (the empty
sha256, AWS's documentation key id) are ignored, a reviewed line can carry
`# pragma: allowlist secret`, and findings already triaged live in a baseline
of fingerprints, sha256(path:rule:value), which survive line moves and do not
contain the secret. Only *new* findings fail the build.

The fixtures are assembled at runtime from pieces so this repository does not
trip real secret scanners. Each true secret is listed in TRUTH for scoring.
"""

import hashlib
import math
import re
import string
import zlib
from collections import Counter

PEM = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
FILES = {
    "app/settings.py": "\n".join([
        "import os",
        "DEBUG = False",
        'SECRET_KEY = "q8Vz2LmX0rT5nWb7Ke1YsP4hJc9GfD3a"',
        "PASSWORD_MIN_LENGTH = 12",
        'password_reset_url = "/accounts/reset/"',
        'DATABASE_URL = "postgresql://app:Wm4tq9Zr2Lx7@db.internal:5432/app"',
        'API_KEY = os.environ["API_KEY"]',
    ]),
    "deploy/.env": "\n".join([
        "AWS_ACCESS_KEY_ID=" + "AKIA" + "Q3VNZ7RJ2KXH5MPW",
        "AWS_SECRET_ACCESS_KEY=" + "u7Ja0Rk3/Pq9Xb2Lm5Nc8Vt1Wz4Yd6Fh" + "Ge3Ks0Q",
        "SLACK_WEBHOOK_TOKEN=changeme",
        "GRAFANA_ADMIN_PASSWORD=${GRAFANA_PASSWORD}",
    ]),
    "scripts/backup.sh": "\n".join([
        "#!/bin/sh",
        "# token rotation is handled by vault",
        'curl -s -H "Authorization: Bearer 7f3b9c1e5a2d8f4b6e0c9a7d3f1b5e8c" \\',
        "     https://backup.internal/api/v1/snapshots",
    ]),
    "keys/deploy_ed25519": "\n".join([
        PEM,
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
        "-----END " + "OPENSSH PRIVATE KEY-----",
    ]),
    "README.md": "\n".join([
        "# backup service",
        "Put your API key in `API_KEY`; a token looks like `xxxxxxxxxxxxxxxxxxxxxxxx`.",
        "Example access key id: " + "AKIA" + "IOSFODNN7EXAMPLE",
    ]),
    "tests/test_digest.py": "\n".join([
        "import hashlib",
        'empty_token_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
        "assert hashlib.sha256(b'').hexdigest() == empty_token_digest",
        'FAKE_TOKEN = "Zx81Kq0LmP2vRt7Nb4Yc9Wd3Hs6Jf5Ga"  # pragma: allowlist secret',
    ]),
    "ci/pipeline.yml": "\n".join([
        "env:",
        "  ACME_DEPLOY: " + "acme_pat_" + "5XRH9jirp0Kfx90B43effC1uUbY7Kw3SgFf1",
        "  # docs placeholder: " + "acme_pat_" + "5XRH9jirp0Kfx90B43effC1uUbY7Kw3SgFfA",
    ]),
}
TRUTH = {("app/settings.py", 3), ("app/settings.py", 6), ("deploy/.env", 1),
         ("deploy/.env", 2), ("scripts/backup.sh", 3), ("keys/deploy_ed25519", 1),
         ("ci/pipeline.yml", 2)}
KNOWN_TEST_VALUES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256(b"")
    "AKIA" + "IOSFODNN7EXAMPLE",  # AWS documentation example
}
BASELINE = {"399e5503907fbdc9"}  # deploy/.env AWS key id: rotated, history rewrite pending

HEX = set("0123456789abcdefABCDEF")
BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
RULES = [
    ("acme-token", re.compile(r"\b(acme_pat_[0-9A-Za-z]{36})\b")),
    ("aws-access-key-id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("private-key", re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
    ("url-credentials", re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:([^@\s/]{6,})@")),
]
ASSIGNMENT = re.compile(
    r"(?i)\b[\w.]*(secret|token|passw(?:or)?d|api_?key|access_key)[\w.]*\s*[:=]\s*[\"']?([^\s\"'`]+)")
BEARER = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]+=*)")


def shannon_entropy(value: str) -> float:
    counts = Counter(value)
    return sum(n / len(value) * math.log2(len(value) / n) for n in counts.values())


def looks_random(value: str) -> bool:
    if len(value) < 16 or value.startswith(("${", "os.environ", "<")):
        return False
    threshold = 3.0 if set(value) <= HEX else 4.0  # hex carries at most 4 bits/char
    return shannon_entropy(value) >= threshold


def acme_checksum_ok(token: str) -> bool:
    body, check = token[9:39], token[39:]
    n, out = zlib.crc32(body.encode()), []
    for _ in range(6):
        n, r = divmod(n, 62)
        out.append(BASE62[r])
    return "".join(reversed(out)) == check


def fingerprint(path: str, rule: str, value: str) -> str:
    return hashlib.sha256(f"{path}:{rule}:{value}".encode()).hexdigest()[:16]


def noncompliant_scan(files: dict[str, str]) -> list[tuple[str, int, str]]:
    hits = []
    for path, text in files.items():
        for n, line in enumerate(text.splitlines(), 1):
            if re.search(r"(?i)password|secret|token|key", line):
                hits.append((path, n, "keyword"))
    return hits


def compliant_scan(files: dict[str, str]) -> list[tuple[str, int, str, str]]:
    """Return (path, line, rule, status) for every candidate, suppressed or not."""
    hits = []
    for path, text in files.items():
        for n, line in enumerate(text.splitlines(), 1):
            rule, value = None, None
            for name, rx in RULES:
                if m := rx.search(line):
                    rule, value = name, m[1]
                    break
            if rule is None:
                m = ASSIGNMENT.search(line) or BEARER.search(line)
                if m and looks_random(m[m.lastindex]):
                    rule, value = f"high-entropy({shannon_entropy(m[m.lastindex]):.2f})", m[m.lastindex]
            if rule is None:
                continue
            if rule == "acme-token" and not acme_checksum_ok(value):
                status = "ignored (checksum fails: placeholder)"
            elif value in KNOWN_TEST_VALUES:
                status = "ignored (published test value)"
            elif "pragma: allowlist secret" in line:
                status = "ignored (allowlist pragma)"
            elif fingerprint(path, rule.split("(")[0], value) in BASELINE:
                status = "baselined"
            else:
                status = "NEW"
            hits.append((path, n, rule, status))
    return hits


def main() -> None:
    naive = {(p, n) for p, n, _ in noncompliant_scan(FILES)}
    print(f"noncompliant: {len(naive & TRUTH)} true, {len(naive - TRUTH)} false, "
          f"{len(TRUTH - naive)} missed")
    print()
    hits = compliant_scan(FILES)
    for path, n, rule, status in hits:
        mark = "TP" if (path, n) in TRUTH else "  "
        print(f"compliant:    {mark} {path}:{n} {rule} -> {status}")
    reported = {(p, n) for p, n, _, s in hits if s in ("NEW", "baselined")}
    new = sum(1 for *_, s in hits if s == "NEW")
    print(f"compliant:    {len(reported & TRUTH)} true, {len(reported - TRUTH)} false, "
          f"{len(TRUTH - reported)} missed; {new} new -> {'fail' if new else 'pass'} the build")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: 4 true, 12 false, 3 missed
#
# compliant:    TP app/settings.py:3 high-entropy(5.00) -> NEW
# compliant:    TP app/settings.py:6 url-credentials -> NEW
# compliant:    TP deploy/.env:1 aws-access-key-id -> baselined
# compliant:    TP deploy/.env:2 high-entropy(5.18) -> NEW
# compliant:    TP scripts/backup.sh:3 high-entropy(3.91) -> NEW
# compliant:    TP keys/deploy_ed25519:1 private-key -> NEW
# compliant:       README.md:3 aws-access-key-id -> ignored (published test value)
# compliant:       tests/test_digest.py:2 high-entropy(3.67) -> ignored (published test value)
# compliant:       tests/test_digest.py:4 high-entropy(5.00) -> ignored (allowlist pragma)
# compliant:    TP ci/pipeline.yml:2 acme-token -> NEW
# compliant:       ci/pipeline.yml:3 acme-token -> ignored (checksum fails: placeholder)
# compliant:    7 true, 0 false, 0 missed; 6 new -> fail the build
