"""Shadowing builtins and stdlib modules — ``list = ...`` and a file named ``random.py``

It is easy to pick obvious names: ``list = fetch_items()``, ``id = row["id"]``,
``type = "admin"``, ``input = sys.stdin.read()``. The code works until a later
line in the same scope calls ``list(...)`` or ``id(...)`` and gets "'list'
object is not callable". The file-level version is worse: save a scratch
script as ``random.py``, ``json.py`` or ``email.py`` and every ``import random``
in that directory now imports your file, because the script's directory comes
first on ``sys.path``. Python 3.13 at least names the culprit in the error.

Review note: never reuse builtin names for variables (linters: A001/A002),
and never name a module after a stdlib or installed package. For scripts that
run from untrusted or shared directories, ``python -P`` (or ``-I``) keeps the
script directory off ``sys.path``. The demo builds a throwaway directory and
runs a child interpreter in it; temp paths are replaced with ``<tmp>``.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

APP = "import random\nprint('roll:', random.randint(1, 6) > 0)\n"
SCRATCH = "# someone's scratch file that happens to be called random.py\nprint('scratch random.py executed')\n"


def builtins_noncompliant(rows: list[dict]) -> int:
    list = [r["name"] for r in rows]            # noqa: A001
    return len(list(set(list)))                 # TypeError at runtime


def builtins_compliant(rows: list[dict]) -> int:
    names = [r["name"] for r in rows]
    return len(list(set(names)))


def run_child(cwd: Path, *flags: str) -> list[str]:
    proc = subprocess.run(
        [sys.executable, *flags, "app.py"],
        cwd=cwd, capture_output=True, text=True, encoding="utf-8",
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1"},
    )
    out = proc.stdout.splitlines()
    if proc.returncode:
        last = proc.stderr.strip().splitlines()[-1]
        # Longest first: on macOS the resolved path adds a /private prefix.
        for prefix in sorted({str(cwd), str(cwd.resolve())}, key=len, reverse=True):
            last = last.replace(prefix, "<tmp>")
        error, sep, hint = last.partition(" (consider")
        out.append(error)
        if sep:
            out.append("  (consider" + hint)
    return out


def main() -> None:
    rows = [{"name": "web01"}, {"name": "db01"}, {"name": "web01"}]
    try:
        builtins_noncompliant(rows)
    except TypeError as exc:
        print("noncompliant builtins:", type(exc).__name__ + ":", exc)
    print("compliant builtins:   ", builtins_compliant(rows), "unique names")

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "app.py").write_text(APP, encoding="utf-8")
        (work / "random.py").write_text(SCRATCH, encoding="utf-8")

        print("noncompliant module name (python app.py):")
        for line in run_child(work):
            print("   |", line)

        print("compliant run (python -P app.py):")
        for line in run_child(work, "-P"):
            print("   |", line)

        (work / "random.py").rename(work / "dice_scratch.py")
        print("compliant rename (python app.py):")
        for line in run_child(work):
            print("   |", line)


if __name__ == "__main__":
    main()

# Output:
# noncompliant builtins: TypeError: 'list' object is not callable
# compliant builtins:    2 unique names
# noncompliant module name (python app.py):
#    | scratch random.py executed
#    | AttributeError: module 'random' has no attribute 'randint'
#    |   (consider renaming '<tmp>/random.py' since it has the same name as the standard library module named 'random' and prevents importing that standard library module)
# compliant run (python -P app.py):
#    | roll: True
# compliant rename (python app.py):
#    | roll: True
