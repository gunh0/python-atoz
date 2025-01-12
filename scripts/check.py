#!/usr/bin/env python3
"""Run every example and compare its stdout with the trailing ``# Output:`` block.

Each example is a single runnable file that ends with a comment block:

    # Output:
    # first line
    #
    # third line (a bare "#" is an empty line)

Examples that need a newer interpreter start with a line such as
``# requires-python: >=3.14`` and are skipped on older versions.

Usage:
    python3 scripts/check.py                 # every example under the sections
    python3 scripts/check.py security practice/pitfalls
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECTIONS = ("sysadmin", "security", "practice")
MARKER = "# Output:"
REQUIRES = "# requires-python: >="
TIMEOUT = 30


def expected_output(source: str) -> list[str] | None:
    lines = source.rstrip("\n").splitlines()
    try:
        start = len(lines) - 1 - lines[::-1].index(MARKER)
    except ValueError:
        return None
    out = []
    for line in lines[start + 1 :]:
        if line == "#":
            out.append("")
        elif line.startswith("# "):
            out.append(line[2:])
        else:
            raise ValueError(f"line in Output block does not start with '# ': {line!r}")
    return out


def examples(targets: list[str]) -> list[Path]:
    paths = [ROOT / t for t in targets] if targets else [ROOT / s for s in SECTIONS]
    found = []
    for p in paths:
        if p.is_file():
            found.append(p)
        elif p.is_dir():
            found.extend(f for f in sorted(p.rglob("*.py")) if not f.name.startswith("_"))
    return found


def required_version(source: str) -> tuple[int, ...]:
    first = source.split("\n", 1)[0]
    if first.startswith(REQUIRES):
        return tuple(int(n) for n in first[len(REQUIRES):].strip().split("."))
    return (0,)


def check(path: Path) -> str | None:
    source = path.read_text(encoding="utf-8")
    if sys.version_info[:2] < required_version(source):
        return "skip"
    try:
        want = expected_output(source)
    except ValueError as exc:
        return str(exc)
    if want is None:
        return "missing '# Output:' block"
    try:
        proc = subprocess.run(
            [sys.executable, path.name],
            cwd=path.parent,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=TIMEOUT,
            env={
                "PYTHONHASHSEED": "0",
                "PYTHONUTF8": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PATH": "/usr/bin:/bin",
                **{k: os.environ[k] for k in ("HOME", "TMPDIR") if k in os.environ},
            },
        )
    except subprocess.TimeoutExpired:
        return f"timed out after {TIMEOUT}s"
    if proc.returncode != 0:
        return f"exit code {proc.returncode}\n{proc.stderr.strip()}"
    got = [line.rstrip() for line in proc.stdout.rstrip("\n").splitlines()]
    want = [line.rstrip() for line in want]
    if got != want:
        diff = [f"  want: {w!r}\n  got:  {g!r}" for w, g in zip(want, got) if w != g][:3]
        return f"output differs ({len(want)} expected lines, {len(got)} actual)\n" + "\n".join(diff)
    return None


def main() -> int:
    files = examples(sys.argv[1:])
    failed = skipped = 0
    for f in files:
        error = check(f)
        if error == "skip":
            skipped += 1
        elif error:
            failed += 1
            print(f"FAIL {f.relative_to(ROOT)}\n{error}\n")
    ran = len(files) - skipped
    note = f", {skipped} skipped for a newer Python" if skipped else ""
    print(f"{ran - failed}/{ran} examples match their Output block{note} "
          f"(Python {sys.version.split()[0]})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
