"""CWE-78: OS command injection — build argument lists, never shell strings

https://cwe.mitre.org/data/definitions/78.html

A "count lines in this upload" helper that formats user input into a string
and runs it with shell=True hands the whole string to /bin/sh. The shell then
interprets ; && | $( ) ` and newlines, so a value like "x; id" becomes two
commands. os.system() and os.popen() always use a shell and have the same
problem.

Pass an argument list to subprocess.run() and leave shell at its default
(False). The program receives each element as exactly one argv entry and no
shell ever parses it, so metacharacters are just bytes in a file name that
does not exist. The injected commands below only echo a marker; in real life
they are curl | sh.
"""

import subprocess
import tempfile
from pathlib import Path

PAYLOADS = [
    "report.txt",                          # the expected input
    "report.txt; echo INJECTED-semicolon",
    "report.txt && echo INJECTED-and",
    "report.txt | echo INJECTED-pipe",
    "$(echo INJECTED-subst >&2)report.txt",
    "`echo INJECTED-backtick >&2`report.txt",
    "report.txt\necho INJECTED-newline",
]


def noncompliant(filename: str, cwd: Path) -> subprocess.CompletedProcess:
    # The shell sees: wc -l < report.txt; echo INJECTED-semicolon
    return subprocess.run(f"wc -l < {filename}", shell=True, cwd=cwd,
                          capture_output=True, text=True)


def compliant(filename: str, cwd: Path) -> subprocess.CompletedProcess:
    # One argv entry, no shell: the payload can only ever be a file name.
    return subprocess.run(["wc", "-l", filename], cwd=cwd,
                          capture_output=True, text=True)


def summary(proc: subprocess.CompletedProcess) -> str:
    # A marker counts only when the injected echo printed it on a line of its own;
    # an error message that merely quotes the bad file name does not count.
    lines = (proc.stdout + proc.stderr).splitlines()
    markers = [ln for ln in lines if ln.startswith("INJECTED-") and " " not in ln]
    first = proc.stdout.split()[:1]
    count = first[0] if first and first[0].isdigit() else "-"
    status = "ok" if proc.returncode == 0 else "failed"
    return f"{status:<6} lines={count:<2} injected={markers or 'none'}"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        (cwd / "report.txt").write_text("alpha\nbeta\ngamma\n")
        for payload in PAYLOADS:
            print(f"input {payload!r}")
            print(f"  noncompliant: {summary(noncompliant(payload, cwd))}")
            print(f"  compliant:    {summary(compliant(payload, cwd))}")


if __name__ == "__main__":
    main()

# Output:
# input 'report.txt'
#   noncompliant: ok     lines=3  injected=none
#   compliant:    ok     lines=3  injected=none
# input 'report.txt; echo INJECTED-semicolon'
#   noncompliant: ok     lines=3  injected=['INJECTED-semicolon']
#   compliant:    failed lines=-  injected=none
# input 'report.txt && echo INJECTED-and'
#   noncompliant: ok     lines=3  injected=['INJECTED-and']
#   compliant:    failed lines=-  injected=none
# input 'report.txt | echo INJECTED-pipe'
#   noncompliant: ok     lines=-  injected=['INJECTED-pipe']
#   compliant:    failed lines=-  injected=none
# input '$(echo INJECTED-subst >&2)report.txt'
#   noncompliant: ok     lines=3  injected=['INJECTED-subst']
#   compliant:    failed lines=-  injected=none
# input '`echo INJECTED-backtick >&2`report.txt'
#   noncompliant: ok     lines=3  injected=['INJECTED-backtick']
#   compliant:    failed lines=-  injected=none
# input 'report.txt\necho INJECTED-newline'
#   noncompliant: ok     lines=3  injected=['INJECTED-newline']
#   compliant:    failed lines=-  injected=none
