"""CWE-798: hard-coded credentials — a secret scanner with regex rules and entropy

https://cwe.mitre.org/data/definitions/798.html

A scanner nobody trusts gets disabled. `grep -i 'password\\|token\\|key'` flags
every settings constant and docstring and still misses a bearer token pasted
into a shell script. Useful scanners combine two signals: provider rules for
formats that are unambiguous (AWS key ids, private key blocks, credentials in
URLs), and for generic assignments a value that is long and *random-looking*,
measured as Shannon entropy per character.

The fixtures are assembled at runtime from pieces so this repository does not
trip real secret scanners. Each true secret is listed in TRUTH, so both
scanners are scored, not just eyeballed. One false positive is left on
purpose: a well-known test digest stored in a variable named like a token.
"""

import math
import re
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
    ]),
    "tests/test_digest.py": "\n".join([
        "import hashlib",
        'empty_token_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
        "assert hashlib.sha256(b'').hexdigest() == empty_token_digest",
    ]),
}
TRUTH = {("app/settings.py", 3), ("app/settings.py", 6), ("deploy/.env", 1),
         ("deploy/.env", 2), ("scripts/backup.sh", 3), ("keys/deploy_ed25519", 1)}

HEX = set("0123456789abcdefABCDEF")
RULES = [
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


def noncompliant_scan(files: dict[str, str]) -> list[tuple[str, int, str]]:
    hits = []
    for path, text in files.items():
        for n, line in enumerate(text.splitlines(), 1):
            if re.search(r"(?i)password|secret|token|key", line):
                hits.append((path, n, "keyword"))
    return hits


def compliant_scan(files: dict[str, str]) -> list[tuple[str, int, str]]:
    hits = []
    for path, text in files.items():
        for n, line in enumerate(text.splitlines(), 1):
            rule = next((name for name, rx in RULES if rx.search(line)), None)
            if rule is None:
                m = ASSIGNMENT.search(line) or BEARER.search(line)
                if m and looks_random(m.group(m.lastindex)):
                    rule = f"high-entropy({shannon_entropy(m.group(m.lastindex)):.2f})"
            if rule:
                hits.append((path, n, rule))
    return hits


def report(label: str, hits: list[tuple[str, int, str]]) -> None:
    found = {(p, n) for p, n, _ in hits}
    for path, n, rule in hits:
        mark = "TP" if (path, n) in TRUTH else "FP"
        print(f"{label} {mark} {path}:{n} {rule}")
    print(f"{label} {len(found & TRUTH)} true, {len(found - TRUTH)} false, "
          f"{len(TRUTH - found)} missed")


def main() -> None:
    report("noncompliant:", noncompliant_scan(FILES))
    print()
    report("compliant:   ", compliant_scan(FILES))
    print()
    for sample in ("changeme", "xxxxxxxxxxxxxxxxxxxxxxxx", "q8Vz2LmX0rT5nWb7Ke1YsP4hJc9GfD3a",
                   "7f3b9c1e5a2d8f4b6e0c9a7d3f1b5e8c"):
        print(f"entropy {shannon_entropy(sample):.2f} bits/char  {sample[:4]}... (len {len(sample)})")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: TP app/settings.py:3 keyword
# noncompliant: FP app/settings.py:4 keyword
# noncompliant: FP app/settings.py:5 keyword
# noncompliant: FP app/settings.py:7 keyword
# noncompliant: TP deploy/.env:1 keyword
# noncompliant: TP deploy/.env:2 keyword
# noncompliant: FP deploy/.env:3 keyword
# noncompliant: FP deploy/.env:4 keyword
# noncompliant: FP scripts/backup.sh:2 keyword
# noncompliant: TP keys/deploy_ed25519:1 keyword
# noncompliant: FP keys/deploy_ed25519:3 keyword
# noncompliant: FP README.md:2 keyword
# noncompliant: FP tests/test_digest.py:2 keyword
# noncompliant: FP tests/test_digest.py:3 keyword
# noncompliant: 4 true, 10 false, 2 missed
#
# compliant:    TP app/settings.py:3 high-entropy(5.00)
# compliant:    TP app/settings.py:6 url-credentials
# compliant:    TP deploy/.env:1 aws-access-key-id
# compliant:    TP deploy/.env:2 high-entropy(5.18)
# compliant:    TP scripts/backup.sh:3 high-entropy(3.91)
# compliant:    TP keys/deploy_ed25519:1 private-key
# compliant:    FP tests/test_digest.py:2 high-entropy(3.67)
# compliant:    6 true, 1 false, 0 missed
#
# entropy 2.75 bits/char  chan... (len 8)
# entropy 0.00 bits/char  xxxx... (len 24)
# entropy 5.00 bits/char  q8Vz... (len 32)
# entropy 3.91 bits/char  7f3b... (len 32)
