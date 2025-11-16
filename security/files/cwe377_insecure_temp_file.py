"""CWE-377: insecure temporary file — mktemp() hands out a name, not a file

https://cwe.mitre.org/data/definitions/377.html

tempfile.mktemp() (deprecated since Python 2.3 and still there) returns a
name that does not exist *yet*. Between that call and open(), anyone who can
write to the directory, which for /tmp is everyone, can create that name as a
symlink to a file you can write. open(name, "w") follows it. Fixed names like
/tmp/myapp.lock or /tmp/export.csv are the same bug without the randomness.
open() also creates the file with mode 0o666 & ~umask, so other users can
usually read it.

mkstemp(), NamedTemporaryFile() and TemporaryDirectory() create the object
atomically with O_CREAT | O_EXCL (fails if anything exists, including a
symlink) and mode 0o600 / 0o700. The race below is made deterministic by
letting the "attacker" act right after mktemp() returns.
"""

import os
import stat
import tempfile
from pathlib import Path


def noncompliant(shared: Path, attacker) -> Path:
    name = tempfile.mktemp(suffix=".csv", dir=shared)
    attacker(Path(name))                      # the race window, made explicit
    with open(name, "w") as f:
        f.write("id,email\n1,ada@example.com\n")
    return Path(name)


def compliant_mkstemp(shared: Path, attacker) -> Path:
    fd, name = tempfile.mkstemp(suffix=".csv", dir=shared)
    attacker(Path(name))                      # too late: the file already exists
    with os.fdopen(fd, "w") as f:
        f.write("id,email\n1,ada@example.com\n")
    return Path(name)


def compliant_named(shared: Path, attacker) -> Path:
    with tempfile.NamedTemporaryFile("w", suffix=".csv", dir=shared, delete=False) as f:
        attacker(Path(f.name))
        f.write("id,email\n1,ada@example.com\n")
    return Path(f.name)


def excl_open(path: Path) -> str:
    """What mkstemp does internally, tried on a name the attacker already planted."""
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        return "created"
    except FileExistsError:
        return "FileExistsError"


def main() -> None:
    os.umask(0o022)
    for fn in (noncompliant, compliant_mkstemp, compliant_named):
        for race in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                shared = Path(tmp) / "tmp"
                shared.mkdir()
                victim = Path(tmp) / "home" / ".bashrc"
                victim.parent.mkdir()
                victim.write_text("export PATH=/usr/bin\n")

                def attacker(name: Path) -> None:
                    if race:
                        try:
                            name.symlink_to(victim)
                        except FileExistsError:
                            pass

                out = fn(shared, attacker)
                kind = "symlink" if out.is_symlink() else stat.filemode(out.stat().st_mode)
                first = victim.read_text().splitlines()[0]
                label = f"{fn.__name__} {'(race)' if race else '(no race)'}"
                print(f"{label:28} temp is {kind:10}  .bashrc starts {first!r}")
    with tempfile.TemporaryDirectory() as tmp:
        planted = Path(tmp) / "planted.csv"
        planted.symlink_to(Path(tmp) / "victim")
        print(f"O_CREAT|O_EXCL on a planted symlink: {excl_open(planted)}")
        print(f"mkdtemp() mode: {stat.filemode(os.stat(tempfile.mkdtemp(dir=tmp)).st_mode)}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant (no race)       temp is -rw-r--r--  .bashrc starts 'export PATH=/usr/bin'
# noncompliant (race)          temp is symlink     .bashrc starts 'id,email'
# compliant_mkstemp (no race)  temp is -rw-------  .bashrc starts 'export PATH=/usr/bin'
# compliant_mkstemp (race)     temp is -rw-------  .bashrc starts 'export PATH=/usr/bin'
# compliant_named (no race)    temp is -rw-------  .bashrc starts 'export PATH=/usr/bin'
# compliant_named (race)       temp is -rw-------  .bashrc starts 'export PATH=/usr/bin'
# O_CREAT|O_EXCL on a planted symlink: FileExistsError
# mkdtemp() mode: drwx------
