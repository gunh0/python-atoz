"""cron_lock v1 — prevent overlapping cron runs with an O_EXCL lock file

`*/5 * * * * sync.sh` assumes the job takes under five minutes. The night it
takes seven (slow NFS, big delta), two copies run at once, then three, and
they fight over the same files. Every job that can overrun needs a lock.

v1 is the classic PID file. os.open(..., O_CREAT | O_EXCL) creates the file
only if it does not exist, atomically, so exactly one run wins; it writes
its PID and removes the file when done. If the file exists, the run checks
whether that PID is still alive (os.kill(pid, 0) sends no signal, it only
checks) and either skips, or treats the lock as stale (the previous run
was killed with -9 and never cleaned up) and takes it over.

Known weaknesses, fixed in v2 with fcntl: a reused PID makes a stale lock
look alive, and two runs that both see a stale lock can both take it over.
The demo starts real child processes; no PIDs are printed.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # exists, owned by another user
        return True
    return True


def acquire(lock: Path) -> str:
    """Return 'acquired', 'busy' or 'acquired (stale lock removed)'."""
    for attempt in range(2):
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            try:
                pid = int(lock.read_text().strip())
            except (ValueError, FileNotFoundError):
                pid = None  # half-written or just removed: treat as stale
            if pid is not None and pid_alive(pid):
                return "busy"
            lock.unlink(missing_ok=True)
            continue
        with os.fdopen(fd, "w") as fh:
            fh.write(f"{os.getpid()}\n")
        return "acquired" if attempt == 0 else "acquired (stale lock removed)"
    return "busy"


def release(lock: Path) -> None:
    lock.unlink(missing_ok=True)


def cron_run(lock: Path) -> int:
    """What the cron entry runs. Exit 0 = did the work, 75 (EX_TEMPFAIL) = skipped."""
    state = acquire(lock)
    if state == "busy":
        print("  run: previous run still active, skipping")
        return 75
    try:
        print(f"  run: lock {state}, syncing")
        return 0
    finally:
        release(lock)


def child(mode: str, lock: Path) -> None:
    if mode == "run":
        sys.exit(cron_run(lock))
    if mode == "crash":  # take the lock, then die like kill -9: no cleanup
        acquire(lock)
        os._exit(137)


def spawn(mode: str, lock: Path) -> int:
    proc = subprocess.run([sys.executable, __file__, "child", mode, str(lock)], capture_output=True, text=True)
    print(proc.stdout, end="")
    return proc.returncode


def main() -> None:
    if sys.argv[1:2] == ["child"]:
        child(sys.argv[2], Path(sys.argv[3]))
        return
    with tempfile.TemporaryDirectory() as tmp:
        lock = Path(tmp) / "sync.lock"

        print("1) a long run holds the lock while cron starts the next one")
        print("  long run:", acquire(lock))
        print("  next run exit code:", spawn("run", lock))
        release(lock)
        print("  next run after release, exit code:", spawn("run", lock))

        print("2) the previous run was killed -9 and left its lock behind")
        print("  crashed run exit code:", spawn("crash", lock))
        print("  lock file left behind:", lock.exists())
        print("  next run exit code:", spawn("run", lock))
        print("  lock file after the run:", lock.exists())

        print("3) the lock file is empty (disk full while writing it)")
        lock.write_text("")
        print("  next run exit code:", spawn("run", lock))


if __name__ == "__main__":
    main()

# Output:
# 1) a long run holds the lock while cron starts the next one
#   long run: acquired
#   run: previous run still active, skipping
#   next run exit code: 75
#   run: lock acquired, syncing
#   next run after release, exit code: 0
# 2) the previous run was killed -9 and left its lock behind
#   crashed run exit code: 137
#   lock file left behind: True
#   run: lock acquired (stale lock removed), syncing
#   next run exit code: 0
#   lock file after the run: False
# 3) the lock file is empty (disk full while writing it)
#   run: lock acquired (stale lock removed), syncing
#   next run exit code: 0
