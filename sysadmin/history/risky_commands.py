"""Shell history audit v2: tokenize with shlex instead of matching regexes

v1 matched regexes against the raw line. Running it over a real team's
history showed both kinds of error. Misses: `rm -r -f /`, `rm -Rf /*`,
`rm -rf --no-preserve-root /`, `curl ... | sudo -E bash`, `bash <(curl ...)`,
`chmod a+rwx`, `sshpass -p`, `ipmitool -P`, `curl -u user:pass`. False
positives: a pipe or a URL *inside a quoted string* (`echo "curl x | sh"`).

v2 tokenizes each line the way the shell would (shlex with punctuation, so
| && ; <( are separate tokens and quotes are honoured), splits it into
simple commands, peels sudo/env/VAR=value, and then checks each command by
program name and parsed options. The v1 regex result is kept as a column so
the difference is visible. Credentials are still masked before printing.
"""

import re
import shlex

HISTORY = """\
rm -rf /srv/app/releases/2026-08-01
rm -r -f /
sudo rm -Rf /*
rm -rf --no-preserve-root /
rm -rf "$BUILD_DIR"/
curl -fsSL https://get.example.org/install.sh | sudo -E bash -s -- --channel stable
bash <(curl -fsSL https://get.example.org/install.sh)
echo "never run curl https://x.example | sh" >> notes.txt
chmod -R a+rwx /srv/shared
chmod 1777 /srv/scratch
chmod 0755 /usr/local/bin/deploy
sshpass -p 'Winter2026!' ssh ops@10.0.5.21
sudo -u postgres mysql -pR00tpw -e 'select 1'
ipmitool -I lanplus -H 10.10.0.21 -U admin -P Bmc!2026pw sensor
curl -u admin:S3cr3t-api https://nas01.example.org/api/v1/status
PGPASSWORD=pgpass99 psql -h db01 -U report
"""

LEGACY_RULES = [  # v1, kept for comparison only
    re.compile(r"\brm\s+-(?:rf|fr)\s+/(?:\*|\s|$)"),
    re.compile(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
    re.compile(r"\bchmod\s+(?:-R\s+)?0?777\b"),
    re.compile(r"\bmysql(?:dump|admin)?\b.*?\s-p[^\s'\"]+|--password[= ]"),
    re.compile(r"://[^/\s:@]+:[^@\s]+@|\b\w*(?:PASSWORD|SECRET|TOKEN)\w*=\S+"),
]

SHELLS = {"sh", "bash", "zsh", "dash", "python3", "perl"}
DOWNLOADERS = {"curl", "wget"}
WRAPPERS = {"sudo", "env", "nohup", "time", "command"}
SEPARATORS = {"|", "||", "&&", ";", "&"}
# program -> options whose value is a password (attached or next token)
PASSWORD_OPTIONS = {"mysql": ("-p", "--password"), "sshpass": ("-p",), "ipmitool": ("-P",),
                    "redis-cli": ("-a",)}
SECRET_ENV = re.compile(r"^\w*(PASSWORD|PASSWD|SECRET|TOKEN)\w*=")


def tokenize(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True, punctuation_chars="|&;<>()")
    lexer.whitespace_split = True
    return list(lexer)


def simple_commands(tokens: list[str]) -> list[tuple[str, list[str], list[str], str]]:
    """Split on separators -> (program, args, env assignments, separator before)."""
    out, current, sep = [], [], ""
    for tok in tokens + [";"]:
        if tok in SEPARATORS:
            env = []
            while current and (current[0] in WRAPPERS or "=" in current[0] or current[0].startswith("-")):
                head = current.pop(0)
                if head in ("-u", "-g", "-C") and current:  # sudo -u USER: skip the value too
                    current.pop(0)
                elif "=" in head and not head.startswith("-"):
                    env.append(head)
            if current:
                out.append((current[0].rsplit("/", 1)[-1], current[1:], env, sep))
            current, sep = [], tok
        else:
            current.append(tok)
    return out


def short_flags(args: list[str]) -> set[str]:
    return {ch for a in args if a.startswith("-") and not a.startswith("--") for ch in a[1:]}


def check_command(prog: str, args: list[str], env: list[str]) -> tuple[list[str], list[str]]:
    findings, secrets = [], []
    targets = [a for a in args if not a.startswith("-")]
    if prog == "rm" and ({"r", "R"} & short_flags(args) or "--recursive" in args):
        if any(t in ("/", "/*") for t in targets):
            findings.append("recursive delete of /")
        elif any(re.match(r"^\$\{?\w+\}?/", t) for t in targets):
            findings.append("rm -r on $VAR/ (empty variable means /)")
    if prog == "chmod" and targets:
        mode = targets[0]
        if re.fullmatch(r"[0-7]{3,4}", mode) and int(mode, 8) & 0o002:
            sticky = " (sticky bit set)" if int(mode, 8) & 0o1000 else ""
            findings.append(f"world-writable chmod {mode}{sticky}")
        elif re.search(r"(^|,)[ugoa]*[oa][ugoa]*\+[rwxXst]*w", mode):
            findings.append(f"world-writable chmod {mode}")
    for option in PASSWORD_OPTIONS.get(prog, ()):
        for i, a in enumerate(args):
            if a == option and i + 1 < len(args):
                secrets.append(args[i + 1])
            elif a.startswith(option) and len(a) > len(option) and not a.startswith("--"):
                secrets.append(a[len(option):])
            elif option.startswith("--") and a.startswith(option + "="):
                secrets.append(a.split("=", 1)[1])
    if prog == "curl":
        for i, a in enumerate(args):
            if a in ("-u", "--user") and i + 1 < len(args) and ":" in args[i + 1]:
                secrets.append(args[i + 1].split(":", 1)[1])
    for a in args:
        if m := re.search(r"://[^/:@]+:([^@]+)@", a):
            secrets.append(m.group(1))
    for assignment in env:
        if SECRET_ENV.match(assignment):
            secrets.append(assignment.split("=", 1)[1])
    if secrets:
        findings.append("credential on command line")
    return findings, secrets


def audit(line: str) -> tuple[list[str], str]:
    try:
        tokens = tokenize(line)
    except ValueError:
        return ["unparseable (unbalanced quotes)"], line
    commands = simple_commands(tokens)
    findings, secrets = [], []
    for n, (prog, args, env, sep) in enumerate(commands):
        f, s = check_command(prog, args, env)
        findings += f
        secrets += s
        if prog in SHELLS and "<(" in args and any(a in DOWNLOADERS for a in args):
            findings.append("download run via process substitution")
        if sep == "|" and prog in SHELLS and commands[n - 1][0] in DOWNLOADERS:
            findings.append("download piped to shell")
    redacted = line
    for secret in secrets:
        redacted = redacted.replace(secret, secret[:2] + "******")
    return findings, redacted


def main() -> None:
    v1_hits = v2_hits = 0
    for number, line in enumerate(HISTORY.splitlines(), start=1):
        legacy = any(rx.search(line) for rx in LEGACY_RULES)
        findings, redacted = audit(line)
        v1_hits += legacy
        v2_hits += bool(findings)
        mark = {(True, True): "both", (False, True): "v2  ", (True, False): "v1  ",
                (False, False): "    "}[(legacy, bool(findings))]
        print(f"{number:>2} {mark} {redacted}")
        if findings:
            print(f"        -> {'; '.join(findings)}")
    print(f"flagged lines: v1 {v1_hits}, v2 {v2_hits}")


if __name__ == "__main__":
    main()

# Output:
#  1      rm -rf /srv/app/releases/2026-08-01
#  2 v2   rm -r -f /
#         -> recursive delete of /
#  3 v2   sudo rm -Rf /*
#         -> recursive delete of /
#  4 v2   rm -rf --no-preserve-root /
#         -> recursive delete of /
#  5 v2   rm -rf "$BUILD_DIR"/
#         -> rm -r on $VAR/ (empty variable means /)
#  6 v2   curl -fsSL https://get.example.org/install.sh | sudo -E bash -s -- --channel stable
#         -> download piped to shell
#  7 v2   bash <(curl -fsSL https://get.example.org/install.sh)
#         -> download run via process substitution
#  8 v1   echo "never run curl https://x.example | sh" >> notes.txt
#  9 v2   chmod -R a+rwx /srv/shared
#         -> world-writable chmod a+rwx
# 10 v2   chmod 1777 /srv/scratch
#         -> world-writable chmod 1777 (sticky bit set)
# 11      chmod 0755 /usr/local/bin/deploy
# 12 v2   sshpass -p 'Wi******' ssh ops@10.0.5.21
#         -> credential on command line
# 13 both sudo -u postgres mysql -pR0****** -e 'select 1'
#         -> credential on command line
# 14 v2   ipmitool -I lanplus -H 10.10.0.21 -U admin -P Bm****** sensor
#         -> credential on command line
# 15 v2   curl -u admin:S3****** https://nas01.example.org/api/v1/status
#         -> credential on command line
# 16 both PGPASSWORD=pg****** psql -h db01 -U report
#         -> credential on command line
# flagged lines: v1 3, v2 13
