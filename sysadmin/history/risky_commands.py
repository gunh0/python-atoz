"""Shell history audit: flag risky commands and redact credentials in the report

Reviewing shell history after an incident (or before handing a box to
another team) is mostly looking for a few classic patterns: recursive delete
of /, piping a download straight into a shell, world-writable permissions,
and secrets typed on the command line, which then sit in plain text in
~/.bash_history and in `ps` output for anyone on the host.

This first version is a table of regexes, one per rule. The report must
never re-leak what it found, so every credential match is masked before
printing. Regexes are a starting point: they are easy to read and review, but
they do not understand quoting or option order, a known limit for now.
"""

import re

HISTORY = """\
cd /srv/app
mkdir -p /srv/app/shared
rm -rf /srv/app/releases/2026-08-*
rm -rf / --no-preserve-root
curl -fsSL https://get.example.org/install.sh | sh
wget -qO- https://example.org/setup | sudo bash
chmod 777 /var/www/uploads
chmod 755 /usr/local/bin/deploy
mysql -u backup -pS3cretPass! -h db01 -e 'show databases'
git clone https://deploy:ghp_x8Kq2LmN0pZr7Tq@git.example.org/ops/infra.git
export DB_PASSWORD=hunter2
curl -o /tmp/install.sh https://get.example.org/install.sh
less /tmp/install.sh
sh /tmp/install.sh
"""

RULES: list[tuple[str, re.Pattern[str]]] = [
    ("recursive delete of /", re.compile(r"\brm\s+-(?:rf|fr)\s+/(?:\*|\s|$)")),
    ("download piped to shell", re.compile(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")),
    ("world-writable chmod", re.compile(r"\bchmod\s+(?:-R\s+)?0?777\b")),
]

# Each pattern has a named group "secret" that gets masked in the report.
SECRETS: list[tuple[str, re.Pattern[str]]] = [
    # mysql's -pPASSWORD has no space; a bare "-p" elsewhere (mkdir -p) is not a secret
    ("password option", re.compile(r"\bmysql(?:dump|admin)?\b.*?\s-p(?P<secret>[^\s'\"]+)")),
    ("password option", re.compile(r"--password[= ](?P<secret>[^\s'\"]+)")),
    ("credentials in URL", re.compile(r"://[^/\s:@]+:(?P<secret>[^@\s]+)@")),
    ("secret in env var", re.compile(r"\b\w*(?:PASSWORD|SECRET|TOKEN)\w*=(?P<secret>\S+)")),
]


def mask(secret: str) -> str:
    return secret[:2] + "*" * 6 if len(secret) > 4 else "*" * 6


def audit(line: str) -> tuple[list[str], str]:
    findings = [name for name, rx in RULES if rx.search(line)]
    redacted = line
    for name, rx in SECRETS:
        for m in rx.finditer(line):
            findings.append(name)
            redacted = redacted.replace(m.group("secret"), mask(m.group("secret")))
    return findings, redacted


def main() -> None:
    lines = HISTORY.splitlines()
    flagged = 0
    for number, line in enumerate(lines, start=1):
        findings, redacted = audit(line)
        if findings:
            flagged += 1
            print(f"{number:>3}: {redacted}")
            print(f"     -> {', '.join(findings)}")
    print(f"{flagged} of {len(lines)} lines flagged")


if __name__ == "__main__":
    main()

# Output:
#   4: rm -rf / --no-preserve-root
#      -> recursive delete of /
#   5: curl -fsSL https://get.example.org/install.sh | sh
#      -> download piped to shell
#   6: wget -qO- https://example.org/setup | sudo bash
#      -> download piped to shell
#   7: chmod 777 /var/www/uploads
#      -> world-writable chmod
#   9: mysql -u backup -pS3****** -h db01 -e 'show databases'
#      -> password option
#  10: git clone https://deploy:gh******@git.example.org/ops/infra.git
#      -> credentials in URL
#  11: export DB_PASSWORD=hu******
#      -> secret in env var
# 7 of 14 lines flagged
