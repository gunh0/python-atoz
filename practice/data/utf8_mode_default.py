# requires-python: >=3.15
"""UTF-8 mode on by default (PEP 686, Python 3.15) — bare ``open()`` stops meaning "locale"

https://peps.python.org/pep-0686/

Python 3.15 turns on UTF-8 mode by default: ``open()`` without ``encoding=``,
``Path.read_text()``, ``subprocess`` text mode and friends now use UTF-8 no
matter what the locale says. Most code never passes ``encoding=``, and on
Linux and macOS with UTF-8 locales nothing changes. The breakage is code that
silently relied on a legacy locale: a script on Korean Windows reading Excel's
CP949 CSV export with a bare ``open()``, or a tool writing files a legacy
consumer reads in the ANSI code page. After the upgrade, the read raises
``UnicodeDecodeError`` (or worse, with ``errors="replace"``, quietly corrupts).

Review note: always pass ``encoding=``. Use ``"utf-8"`` for your own files,
the producer's real codec (``"cp949"``, ``"cp1252"``) for legacy inputs, and
``encoding="locale"`` only when you really mean the user's locale. Run tests
with ``-X warn_default_encoding`` to find every call that relies on a default.
``-X utf8=0`` / ``PYTHONUTF8=0`` is the opt-out, not the fix.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

LEGACY_EXPORT = "이름,금액\n김지우,12000\n".encode("cp949")   # Korean Excel CSV export

# Runs in a child interpreter with a clean environment, so it sees the real
# default (the example checker itself forces PYTHONUTF8=1 for its own runs).
PROBE = """
import codecs, locale, sys
def name(enc):
    return codecs.lookup(enc).name
with open(sys.argv[1]) as f:                      # code under review
    enc = f.encoding
    try:
        f.read()
        result = "read ok"
    except UnicodeDecodeError:
        result = "UnicodeDecodeError"
with open(sys.argv[1], encoding="locale") as g:
    loc = g.encoding
print(f"utf8_mode={sys.flags.utf8_mode}  bare open() is utf-8: {name(enc) == 'utf-8'} -> {result}"
      f"  encoding='locale' follows locale: {name(loc) == name(locale.getencoding())}")
"""


def read_noncompliant(path: Path) -> str:
    with open(path) as f:                      # relies on the default encoding
        return f.read()


def read_compliant(path: Path) -> str:
    with open(path, encoding="cp949") as f:    # the producer's real codec
        return f.read()


def child(*flags: str, path: Path, lc_all: str) -> str:
    # No PYTHONUTF8 in the environment, so the interpreter default applies.
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": lc_all, "PYTHONCOERCECLOCALE": "0"}
    proc = subprocess.run([sys.executable, *flags, "-c", PROBE, str(path)],
                          capture_output=True, text=True, encoding="utf-8", env=env)
    return (proc.stdout + proc.stderr).strip()


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "export.csv"
        path.write_bytes(LEGACY_EXPORT)

        try:
            read_noncompliant(path)
        except UnicodeDecodeError as exc:
            print(f"noncompliant: bare open() -> UnicodeDecodeError ({exc.encoding}: {exc.reason})")
        print("compliant:    encoding='cp949' ->", read_compliant(path).splitlines())

        # C.UTF-8 is not the plain C locale, so 3.14 would report utf8_mode=0 here;
        # 3.15 turns the mode on regardless of the locale.
        print("default, LC_ALL=C.UTF-8:", child(path=path, lc_all="C.UTF-8"))
        # Opt-out under the ASCII C locale: bare open() follows the locale again.
        print("-X utf8=0, LC_ALL=C:    ", child("-X", "utf8=0", path=path, lc_all="C"))

        env = {"PATH": "/usr/bin:/bin"}
        proc = subprocess.run(
            [sys.executable, "-X", "warn_default_encoding", "-c", f"open({str(path)!r}).close()"],
            capture_output=True, text=True, encoding="utf-8", env=env)
        warning = next(line for line in proc.stderr.splitlines() if "EncodingWarning" in line)
        print("-X warn_default_encoding:", warning.split(": ", 1)[1])


if __name__ == "__main__":
    main()

# Output:
# noncompliant: bare open() -> UnicodeDecodeError (utf-8: invalid start byte)
# compliant:    encoding='cp949' -> ['이름,금액', '김지우,12000']
# default, LC_ALL=C.UTF-8: utf8_mode=1  bare open() is utf-8: True -> UnicodeDecodeError  encoding='locale' follows locale: True
# -X utf8=0, LC_ALL=C:     utf8_mode=0  bare open() is utf-8: False -> UnicodeDecodeError  encoding='locale' follows locale: True
# -X warn_default_encoding: EncodingWarning: 'encoding' argument not specified
