"""CWE-88: argument injection — a file name that starts with "-" is an option

https://cwe.mitre.org/data/definitions/88.html

Switching from shell strings to argument lists (cwe78) stops the shell, but
not the program you call: it still runs getopt over argv, and any element
that starts with "-" is parsed as an option. A "sort this uploaded file"
endpoint calling ["sort", name] with name "-ovictim.txt" makes sort read stdin
(empty here) and write the result to victim.txt, truncating it. The same trick
gives `git --upload-pack=...`, `tar --checkpoint-action=exec=...`,
`curl -o`, `ssh -oProxyCommand=...`: real code execution with no shell.

Fixes, best combined: end options with "--" so everything after it is an
operand; or make the operand unambiguous (./name or an absolute path); and
validate input against an allow-list that cannot start with "-".
"""

import re
import subprocess
import tempfile
from pathlib import Path

SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._]{0,63}")
INPUTS = ["names.txt", "-ovictim.txt", "--output=victim.txt"]


def run(argv: list[str], cwd: Path) -> str:
    proc = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True)
    return f"exit={proc.returncode} stdout={proc.stdout.split()}"


def noncompliant(name: str, cwd: Path) -> str:
    return run(["sort", name], cwd)


def compliant_double_dash(name: str, cwd: Path) -> str:
    return run(["sort", "--", name], cwd)


def compliant_dot_slash(name: str, cwd: Path) -> str:
    return run(["sort", f"./{name}"], cwd)


def compliant_allow_list(name: str, cwd: Path) -> str:
    if not SAFE_NAME.fullmatch(name):
        return "rejected by allow-list"
    return run(["sort", "--", name], cwd)


def victim_state(cwd: Path) -> str:
    data = (cwd / "victim.txt").read_text()
    return "intact" if data else "TRUNCATED"


def main() -> None:
    for fn in (noncompliant, compliant_double_dash, compliant_dot_slash, compliant_allow_list):
        print(fn.__name__)
        for name in INPUTS:
            with tempfile.TemporaryDirectory() as tmp:
                cwd = Path(tmp)
                (cwd / "names.txt").write_text("carol\nalice\nbob\n")
                (cwd / "victim.txt").write_text("important data\n")
                result = fn(name, cwd)
                print(f"  {name!r:24} {result:40} victim.txt {victim_state(cwd)}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant
#   'names.txt'              exit=0 stdout=['alice', 'bob', 'carol']  victim.txt intact
#   '-ovictim.txt'           exit=0 stdout=[]                         victim.txt TRUNCATED
#   '--output=victim.txt'    exit=0 stdout=[]                         victim.txt TRUNCATED
# compliant_double_dash
#   'names.txt'              exit=0 stdout=['alice', 'bob', 'carol']  victim.txt intact
#   '-ovictim.txt'           exit=2 stdout=[]                         victim.txt intact
#   '--output=victim.txt'    exit=2 stdout=[]                         victim.txt intact
# compliant_dot_slash
#   'names.txt'              exit=0 stdout=['alice', 'bob', 'carol']  victim.txt intact
#   '-ovictim.txt'           exit=2 stdout=[]                         victim.txt intact
#   '--output=victim.txt'    exit=2 stdout=[]                         victim.txt intact
# compliant_allow_list
#   'names.txt'              exit=0 stdout=['alice', 'bob', 'carol']  victim.txt intact
#   '-ovictim.txt'           rejected by allow-list                   victim.txt intact
#   '--output=victim.txt'    rejected by allow-list                   victim.txt intact
