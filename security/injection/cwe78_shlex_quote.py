"""CWE-78: when a shell string is unavoidable, quote with shlex.quote

https://cwe.mitre.org/data/definitions/78.html

Sometimes a command line must be a single string: the remote side of
`ssh host '<cmd>'`, a `bash -c` in a container entrypoint, a crontab line. The
usual hand-rolled fix is wrapping the value in quotes, and both variants fail:
inside "double quotes" the shell still expands $(...) and backticks, and
'single quotes' end at the first ' in the input.

shlex.quote() wraps the value in single quotes and rewrites every embedded '
as '"'"', which POSIX sh cannot misread. Combine it with "--" so a value that
starts with "-" is not taken as an option (see cwe88). It is POSIX-only: it
does not protect cmd.exe or PowerShell. If you control both ends, prefer
argument lists and connect pipelines with Popen instead of a shell.
"""

import shlex
import subprocess
import tempfile
from pathlib import Path

LOG = "GET /index.html 200\nGET /it's-me 404\nPOST /login 302\n"
TERMS = [
    "GET",
    "it's",
    '"; echo INJECTED-dq; "',
    "$(echo INJECTED-subst >&2)",
    "'; echo INJECTED-sq; '",
]


def run_sh(script: str, cwd: Path) -> str:
    """Stand-in for `ssh host <script>`: the string is parsed by a remote sh."""
    proc = subprocess.run(["sh", "-c", script], cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True)
    lines = (proc.stdout + proc.stderr).splitlines()
    markers = [ln for ln in lines if ln.startswith("INJECTED-") and " " not in ln]
    count = proc.stdout.strip() if proc.stdout.strip().isdigit() else "-"
    return f"count={count} injected={markers or 'none'}"


def noncompliant_double(term: str) -> str:
    return f'grep -c "{term}" access.log'


def noncompliant_single(term: str) -> str:
    return f"grep -c '{term}' access.log"


def compliant(term: str) -> str:
    return f"grep -c -- {shlex.quote(term)} access.log"


def compliant_pipeline(term: str, cwd: Path) -> str:
    """No shell at all: grep | wc wired together with two Popen objects."""
    grep = subprocess.Popen(["grep", "--", term, "access.log"], cwd=cwd,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    wc = subprocess.run(["wc", "-l"], stdin=grep.stdout, capture_output=True, text=True)
    grep.stdout.close()
    grep.wait()
    return f"count={wc.stdout.strip()} injected=none"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        (cwd / "access.log").write_text(LOG)
        for term in TERMS:
            print(f"term {term!r}")
            print(f"  noncompliant \"...\": {run_sh(noncompliant_double(term), cwd)}")
            print(f"  noncompliant '...': {run_sh(noncompliant_single(term), cwd)}")
            print(f"  compliant quote:   {run_sh(compliant(term), cwd)}")
            print(f"  compliant popen:   {compliant_pipeline(term, cwd)}")
        print()
        print("shlex.quote(\"it's\")  ->", shlex.quote("it's"))
        print("shlex.join(argv)     ->", shlex.join(["grep", "-c", "--", "a b;c", "access.log"]))
        print("shlex.split(joined)  ->", shlex.split(shlex.join(["grep", "a b;c"])))


if __name__ == "__main__":
    main()

# Output:
# term 'GET'
#   noncompliant "...": count=2 injected=none
#   noncompliant '...': count=2 injected=none
#   compliant quote:   count=2 injected=none
#   compliant popen:   count=2 injected=none
# term "it's"
#   noncompliant "...": count=1 injected=none
#   noncompliant '...': count=- injected=none
#   compliant quote:   count=1 injected=none
#   compliant popen:   count=1 injected=none
# term '"; echo INJECTED-dq; "'
#   noncompliant "...": count=- injected=['INJECTED-dq']
#   noncompliant '...': count=0 injected=none
#   compliant quote:   count=0 injected=none
#   compliant popen:   count=0 injected=none
# term '$(echo INJECTED-subst >&2)'
#   noncompliant "...": count=3 injected=['INJECTED-subst']
#   noncompliant '...': count=0 injected=none
#   compliant quote:   count=0 injected=none
#   compliant popen:   count=0 injected=none
# term "'; echo INJECTED-sq; '"
#   noncompliant "...": count=0 injected=none
#   noncompliant '...': count=- injected=['INJECTED-sq']
#   compliant quote:   count=0 injected=none
#   compliant popen:   count=0 injected=none
#
# shlex.quote("it's")  -> 'it'"'"'s'
# shlex.join(argv)     -> grep -c -- 'a b;c' access.log
# shlex.split(joined)  -> ['grep', 'a b;c']
