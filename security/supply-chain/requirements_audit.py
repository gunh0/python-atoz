"""CWE-829: untrusted dependency sources — audit requirements for pins, URLs and VCS refs

https://cwe.mitre.org/data/definitions/829.html

A requirements file decides what code runs in production. `requests>=2.31`
installs whatever is newest on deploy day, `git+https://...@main` installs
whatever someone pushed to a branch, a bare https URL has no integrity check,
and `--extra-index-url` lets a public package with the same name as your
internal one win the version race (dependency confusion).

A substring check for "==" misses most of this (`numpy==2.*` contains "==").
The audit below parses each line the way pip would read it, classifies it, and
reports a severity, so it can gate CI: anything at ERROR fails the build.
"""

import re

REQUIREMENTS = """\
# service dependencies
--index-url http://mirror.example.internal/simple
--extra-index-url https://pypi.example.internal/simple
--trusted-host mirror.example.internal
Django==5.1.4
flask[async]==3.1.0 ; python_version >= "3.10"
pyyaml===6.0.2
requests>=2.31
urllib3
numpy==2.*
cryptography~=43.0
internal-utils @ git+https://git.example.internal/platform/internal-utils.git@main
auth-client @ git+https://git.example.internal/platform/auth-client.git@3f2c1a9d8e7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a
https://files.example.com/pkgs/legacy_tool-1.2.tar.gz
report-kit @ https://files.example.com/pkgs/report_kit-0.9.tar.gz#sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
-e ./libs/shared
-r requirements-dev.txt
"""

REQ = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*"
                 r"(?P<spec>[^;@]*?)\s*(?:;\s*(?P<marker>.*))?$")
SPEC = re.compile(r"^(===|==|~=|!=|<=|>=|<|>)\s*(\S+)$")


def noncompliant_audit(text: str) -> list[tuple[int, str, str]]:
    return [(n, "ERROR", "not pinned") for n, line in enumerate(text.splitlines(), 1)
            if line.strip() and not line.startswith("#") and "==" not in line]


def _audit_option(line: str) -> tuple[str, str]:
    opt, _, value = line.partition(" ")
    if opt == "--extra-index-url":
        return "ERROR", "extra index: public packages can shadow internal names (dependency confusion)"
    if opt == "--index-url" and value.startswith("http://"):
        return "ERROR", "index over plain http"
    if opt == "--trusted-host":
        return "ERROR", f"TLS verification disabled for {value}"
    if opt == "-e":
        return "WARN", "editable/local path: not reproducible outside this checkout"
    if opt in ("-r", "-c"):
        return "INFO", f"includes {value}: audit it too"
    return "WARN", f"unknown option {opt}"


def _audit_direct(name: str, url: str) -> tuple[str, str]:
    if url.startswith("git+"):
        ref = url.rsplit("@", 1)[-1] if url.count("@") else ""
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            return "WARN", f"{name}: VCS pinned to a commit, but no hash check of the build"
        return "ERROR", f"{name}: VCS ref {ref or 'default branch'!r} is mutable"
    if "#sha256=" in url:
        return "OK", f"{name}: direct URL with sha256"
    return "ERROR", f"{name}: direct URL without a hash"


def compliant_audit(text: str) -> list[tuple[int, str, str]]:
    findings = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            findings.append((n, *_audit_option(line)))
            continue
        if re.match(r"^[a-z+]+://", line):  # bare URL, no name at all
            findings.append((n, *_audit_direct(line.rsplit("/", 1)[-1], line)))
            continue
        if " @ " in line:
            name, url = (part.strip() for part in line.split(" @ ", 1))
            findings.append((n, *_audit_direct(name, url)))
            continue
        m = REQ.match(line)
        if not m:
            findings.append((n, "ERROR", f"cannot parse {line!r}"))
            continue
        name, spec = m["name"], m["spec"].replace(" ", "")
        specs = [SPEC.match(s) for s in spec.split(",")] if spec else []
        if not specs:
            findings.append((n, "ERROR", f"{name}: no version constraint"))
        elif len(specs) == 1 and specs[0] and specs[0][1] in ("==", "===") and "*" not in specs[0][2]:
            findings.append((n, "OK", f"{name} pinned to {specs[0][2]}"))
        else:
            findings.append((n, "ERROR", f"{name}: range {spec!r} is not an exact pin"))
    return findings


def main() -> None:
    findings = compliant_audit(REQUIREMENTS)
    severity = {n: sev for n, sev, _ in findings}
    naive = [n for n, _, _ in noncompliant_audit(REQUIREMENTS)]
    print(f"noncompliant: flagged lines {naive}")
    print(f"noncompliant: missed problems on lines {[n for n, sev, _ in findings if sev != 'OK' and n not in naive]}")
    print(f"noncompliant: wrong 'not pinned' on lines {[n for n in naive if severity.get(n) == 'OK']}")
    print()
    for n, sev, message in findings:
        print(f"compliant: line {n:2} {sev:5} {message}")
    errors = sum(1 for _, sev, _ in findings if sev == "ERROR")
    print(f"compliant: {errors} errors -> {'fail' if errors else 'pass'} the build")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: flagged lines [2, 3, 4, 8, 9, 11, 12, 13, 14, 15, 16, 17]
# noncompliant: missed problems on lines [10]
# noncompliant: wrong 'not pinned' on lines [15]
#
# compliant: line  2 ERROR index over plain http
# compliant: line  3 ERROR extra index: public packages can shadow internal names (dependency confusion)
# compliant: line  4 ERROR TLS verification disabled for mirror.example.internal
# compliant: line  5 OK    Django pinned to 5.1.4
# compliant: line  6 OK    flask pinned to 3.1.0
# compliant: line  7 OK    pyyaml pinned to 6.0.2
# compliant: line  8 ERROR requests: range '>=2.31' is not an exact pin
# compliant: line  9 ERROR urllib3: no version constraint
# compliant: line 10 ERROR numpy: range '==2.*' is not an exact pin
# compliant: line 11 ERROR cryptography: range '~=43.0' is not an exact pin
# compliant: line 12 ERROR internal-utils: VCS ref 'main' is mutable
# compliant: line 13 WARN  auth-client: VCS pinned to a commit, but no hash check of the build
# compliant: line 14 ERROR legacy_tool-1.2.tar.gz: direct URL without a hash
# compliant: line 15 OK    report-kit: direct URL with sha256
# compliant: line 16 WARN  editable/local path: not reproducible outside this checkout
# compliant: line 17 INFO  includes requirements-dev.txt: audit it too
# compliant: 9 errors -> fail the build
