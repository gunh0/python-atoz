"""Typosquatting — flag new dependencies one typo away from a popular package

https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse

Attackers publish "reqeusts", "urlib3" or "colourama" and wait for a tired
human (or a code generator) to type it. A blocklist of known-bad names is
always one upload behind. The cheap, proactive check runs when a dependency is
added: if the name is not itself a well-known package but is within a small
edit distance of one, stop and ask.

v2 closes the gaps of plain edit distance. Names are compared after PEP 503
normalisation, so "Python_Dateutil" is python-dateutil and no longer a false
alarm. Confusable characters are folded first (0->o, 1/I->l, rn->m, vv->w), so
"rnatpl0tlib" is caught even though it is three edits away. Decorations that
add no meaning ("python-", "-py", ...) and reordered words ("dateutil-python")
are matched explicitly.
"""

import re

POPULAR = [  # a slice of the most-downloaded PyPI projects (embedded, no network)
    "requests", "urllib3", "boto3", "boto", "botocore", "setuptools", "certifi",
    "idna", "charset-normalizer", "python-dateutil", "six", "numpy", "pandas",
    "pyyaml", "typing-extensions", "cryptography", "pip", "wheel", "attrs",
    "colorama", "jinja2", "markupsafe", "click", "django", "flask", "pytest",
    "jellyfish", "beautifulsoup4", "pillow", "pydantic", "packaging", "rsa",
    "matplotlib", "requests-toolbelt",
]
KNOWN_BAD = {"python3-dateutil", "jeilyfish"}  # yesterday's incident reports
CONFUSABLES = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("i", "l")]  # I is i after lower()
AFFIXES = re.compile(r"^(python3?-|py-)|(-python3?|-py)$")


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


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()  # PEP 503


def fold(name: str) -> str:
    for src, dst in CONFUSABLES:
        name = name.replace(src, dst)
    return name


NORMALIZED = {normalize(p) for p in POPULAR}
FOLDED = {fold(p): p for p in NORMALIZED}


def noncompliant_check(name: str) -> str:
    return "blocked" if name.lower() in KNOWN_BAD else "ok"


def distance_only(name: str) -> str:
    """v1: lowercase plus edit distance."""
    name = name.lower()
    if name in POPULAR:
        return "ok"
    dist, target = min((osa_distance(name, p), p) for p in POPULAR)
    return f"~{target}" if dist <= (1 if len(name) <= 5 else 2) else "unknown"


def compliant_check(name: str) -> str:
    norm = normalize(name)
    if norm in NORMALIZED:
        return "ok (popular)"
    if fold(norm) in FOLDED:
        return f"SUSPICIOUS: confusable with {FOLDED[fold(norm)]!r}"
    stripped = AFFIXES.sub("", norm)
    if stripped != norm and stripped in NORMALIZED:
        return f"SUSPICIOUS: decorated {stripped!r}"
    for popular in NORMALIZED:
        if "-" in popular and sorted(popular.split("-")) == sorted(norm.split("-")):
            return f"SUSPICIOUS: reordered {popular!r}"
    dist, target = min((osa_distance(fold(norm), fold(p)), p) for p in NORMALIZED)
    if dist <= (1 if len(norm) <= 5 else 2):
        return f"SUSPICIOUS: {dist} edit(s) from {target!r}"
    return "unknown (review manually)"


def main() -> None:
    added = ["requests", "Python_Dateutil", "reqeusts", "jeIlyfish", "rnatpl0tlib",
             "dateutil-python", "python-requests", "requests-py", "requests-toolbelt",
             "c1ick", "sixx", "httpx-cache-tools"]
    print(f"{'name':18} {'blocklist':10} {'v1':17} v2")
    for name in added:
        print(f"{name:18} {noncompliant_check(name):10} {distance_only(name):17} {compliant_check(name)}")


if __name__ == "__main__":
    main()

# Output:
# name               blocklist  v1                v2
# requests           ok         ok                ok (popular)
# Python_Dateutil    ok         ~python-dateutil  ok (popular)
# reqeusts           ok         ~requests         SUSPICIOUS: 1 edit(s) from 'requests'
# jeIlyfish          blocked    ~jellyfish        SUSPICIOUS: confusable with 'jellyfish'
# rnatpl0tlib        ok         unknown           SUSPICIOUS: confusable with 'matplotlib'
# dateutil-python    ok         unknown           SUSPICIOUS: reordered 'python-dateutil'
# python-requests    ok         unknown           SUSPICIOUS: decorated 'requests'
# requests-py        ok         unknown           SUSPICIOUS: decorated 'requests'
# requests-toolbelt  ok         ok                ok (popular)
# c1ick              ok         ~click            SUSPICIOUS: confusable with 'click'
# sixx               ok         ~six              SUSPICIOUS: 1 edit(s) from 'six'
# httpx-cache-tools  ok         unknown           unknown (review manually)
