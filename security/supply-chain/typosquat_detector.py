"""Typosquatting — flag new dependencies one typo away from a popular package

https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse

Attackers publish "reqeusts", "urlib3" or "colourama" and wait for a tired
human (or a code generator) to type it. A blocklist of known-bad names is
always one upload behind. The cheap, proactive check runs when a dependency is
added: if the name is not itself a well-known package but is within a small
edit distance of one, stop and ask.

Damerau-Levenshtein (optimal string alignment) counts a swapped pair of
letters as one edit, which is the most common typo. The distance limit scales
with length so short names like "six" do not match half the index.
"""

POPULAR = [  # a slice of the most-downloaded PyPI projects (embedded, no network)
    "requests", "urllib3", "boto3", "boto", "botocore", "setuptools", "certifi",
    "idna", "charset-normalizer", "python-dateutil", "six", "numpy", "pandas",
    "pyyaml", "typing-extensions", "cryptography", "pip", "wheel", "attrs",
    "colorama", "jinja2", "markupsafe", "click", "django", "flask", "pytest",
    "jellyfish", "beautifulsoup4", "pillow", "pydantic", "packaging", "rsa",
]
KNOWN_BAD = {"python3-dateutil", "jeilyfish"}  # yesterday's incident reports


def osa_distance(a: str, b: str) -> int:
    """Optimal string alignment distance: insert, delete, substitute, transpose."""
    d = [[i + j if i * j == 0 else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def noncompliant_check(name: str) -> str:
    return "blocked (known bad)" if name.lower() in KNOWN_BAD else "ok"


def compliant_check(name: str) -> str:
    name = name.lower()
    if name in POPULAR:
        return "ok (popular)"
    limit = 1 if len(name) <= 5 else 2
    close = sorted((osa_distance(name, p), p) for p in POPULAR)
    dist, target = close[0]
    if dist <= limit:
        return f"SUSPICIOUS: {dist} edit(s) from {target!r}"
    return "unknown (review manually)"


def main() -> None:
    added = ["requests", "reqeusts", "urlib3", "colourama", "djanga", "python3-dateutil",
             "jeIlyfish", "boto", "bot03", "sixx", "rsa", "httpx-cache-tools"]
    for name in added:
        print(f"{name:18} noncompliant: {noncompliant_check(name):20} compliant: {compliant_check(name)}")


if __name__ == "__main__":
    main()

# Output:
# requests           noncompliant: ok                   compliant: ok (popular)
# reqeusts           noncompliant: ok                   compliant: SUSPICIOUS: 1 edit(s) from 'requests'
# urlib3             noncompliant: ok                   compliant: SUSPICIOUS: 1 edit(s) from 'urllib3'
# colourama          noncompliant: ok                   compliant: SUSPICIOUS: 1 edit(s) from 'colorama'
# djanga             noncompliant: ok                   compliant: SUSPICIOUS: 1 edit(s) from 'django'
# python3-dateutil   noncompliant: blocked (known bad)  compliant: SUSPICIOUS: 1 edit(s) from 'python-dateutil'
# jeIlyfish          noncompliant: blocked (known bad)  compliant: SUSPICIOUS: 1 edit(s) from 'jellyfish'
# boto               noncompliant: ok                   compliant: ok (popular)
# bot03              noncompliant: ok                   compliant: SUSPICIOUS: 1 edit(s) from 'boto3'
# sixx               noncompliant: ok                   compliant: SUSPICIOUS: 1 edit(s) from 'six'
# rsa                noncompliant: ok                   compliant: ok (popular)
# httpx-cache-tools  noncompliant: ok                   compliant: unknown (review manually)
