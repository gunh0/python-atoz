"""cron_lock v2 — fcntl.flock: the kernel owns the lock, nothing goes stale

v1's PID file had two holes: a stale lock can look alive when the PID has
been reused, and two runs that both find a stale lock can both take it
over. Both come from the same design flaw: the lock is a file's existence,
and cleaning it up is the job of a process that may be dead.

v2 asks the kernel instead. flock(LOCK_EX | LOCK_NB) on an open file either
succeeds or fails at once with BlockingIOError, atomically. The lock belongs
to the open file, so it disappears when the holder exits for any reason,
kill -9 included; there is no stale state to detect. Rules that follow:

- open the lock file without truncating it ("a"), and never delete it:
  unlinking lets a waiter lock an inode nobody else can see any more
- the PID written into it is for humans only (`cat sync.lock`), never trusted
- flock is for local filesystems; on NFS use a lock service or run the job
  on one host. `flock -n /run/lock/sync.lock sync.sh` (util-linux) is the
  same mechanism for a pure crontab line

The demo uses real processes: a holder that keeps the lock until told to
exit, and the same holder killed with SIGKILL.
"""

import contextlib
import fcntl
import os
import subprocess
import sys
import tempfile
from pathlib import Path


class Busy(Exception):
    pass


@contextlib.contextmanager
def cron_lock(path: Path):
    with open(path, "a+", encoding="ascii") as fh:  # "a+": create if missing, never truncate
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Busy(path.name) from None
        fh.truncate(0)  # safe now: we hold the lock
        fh.write(f"{os.getpid()}\n")
        fh.flush()
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def cron_run(lock: Path) -> int:
    """What the cron entry runs. Exit 0 = did the work, 75 (EX_TEMPFAIL) = skipped."""
    try:
        with cron_lock(lock):
            print("  run: lock acquired, syncing")
            return 0
    except Busy:
        print("  run: previous run still active, skipping")
        return 75


def hold(lock: Path) -> None:
    """Child: take the lock, report, then wait until stdin closes."""
    with cron_lock(lock):
        print("locked", flush=True)
        sys.stdin.read()


def start_holder(lock: Path) -> subprocess.Popen:
    proc = subprocess.Popen([sys.executable, __file__, "hold", str(lock)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline() == "locked\n"  # wait until it really holds the lock
    return proc


def main() -> None:
    if sys.argv[1:2] == ["hold"]:
        hold(Path(sys.argv[2]))
        return
    with tempfile.TemporaryDirectory() as tmp:
        lock = Path(tmp) / "sync.lock"

        print("1) a long run holds the lock while cron starts the next one")
        holder = start_holder(lock)
        print("  next run exit code:", cron_run(lock))
        holder.stdin.close()  # let the long run finish normally
        print("  long run exit code:", holder.wait())
        print("  next run exit code:", cron_run(lock))

        print("2) the long run is killed -9 while holding the lock")
        holder = start_holder(lock)
        holder.kill()
        print("  holder exit code:", holder.wait())
        holder.stdin.close()
        holder.stdout.close()
        print("  lock file still there:", lock.exists(), "(harmless, it is never deleted)")
        print("  next run exit code:", cron_run(lock))

        print("3) garbage in the lock file does not matter")
        lock.write_text("not a pid\n")
        print("  next run exit code:", cron_run(lock))
        print("  file now records the last holder:", lock.read_text().strip().isdigit())


if __name__ == "__main__":
    main()

# Output:
# 1) a long run holds the lock while cron starts the next one
#   run: previous run still active, skipping
#   next run exit code: 75
#   long run exit code: 0
#   run: lock acquired, syncing
#   next run exit code: 0
# 2) the long run is killed -9 while holding the lock
#   holder exit code: -9
#   lock file still there: True (harmless, it is never deleted)
#   run: lock acquired, syncing
#   next run exit code: 0
# 3) garbage in the lock file does not matter
#   run: lock acquired, syncing
#   next run exit code: 0
#   file now records the last holder: True
