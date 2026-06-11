"""Subprocess timeouts — kill the child, and the children it started

https://docs.python.org/3/library/subprocess.html#subprocess.Popen.communicate

Wrappers around external tools usually call `subprocess.run(cmd)`
with no timeout at all, so one hung `ssh` or `curl` hangs the job forever.
Adding `timeout=` is the first fix: `run()` kills the direct child and raises
TimeoutExpired. It is not the whole fix. Shell scripts, `ssh`, package managers
and test runners start children of their own; killing only the direct child
leaves the grandchild running, still holding your stdout pipe, so the
"cleanup" `communicate()` blocks until the grandchild finishes on its own.

Start the child in its own session (`start_new_session=True`, i.e. a new
process group) and on timeout kill the whole group with `os.killpg`. Then
`communicate()` returns at once: end-of-file on the pipe proves every process
that held it is gone. POSIX only; Windows needs job objects.
"""

import os
import signal
import subprocess
import sys

SLEEPER = "import time; time.sleep(30)"
# A child that starts a grandchild (sharing its stdout), reports its PID, then hangs.
PARENT_OF_SLEEPER = (
    "import subprocess, sys, time\n"
    f"g = subprocess.Popen([sys.executable, '-c', {SLEEPER!r}])\n"
    "print(g.pid, flush=True)\n"
    "time.sleep(30)\n"
)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def baseline() -> None:
    try:
        subprocess.run([sys.executable, "-c", SLEEPER], timeout=0.3)
    except subprocess.TimeoutExpired as exc:
        print(f"run(timeout=0.3) on a single process -> TimeoutExpired after {exc.timeout}s, "
              "child killed")


def noncompliant() -> None:
    proc = subprocess.Popen([sys.executable, "-c", PARENT_OF_SLEEPER],
                            stdout=subprocess.PIPE, text=True)
    grandchild = int(proc.stdout.readline())
    try:
        proc.communicate(timeout=0.3)
    except subprocess.TimeoutExpired:
        proc.kill()  # what run() does: only the direct child
        proc.wait()
        print(f"noncompliant: child killed (returncode {proc.returncode})")
        try:
            proc.communicate(timeout=1.0)
            print("noncompliant: communicate() returned")
        except subprocess.TimeoutExpired:
            print("noncompliant: communicate() still blocked: the grandchild holds the pipe")
    print(f"noncompliant: grandchild still running: {alive(grandchild)}")
    os.kill(grandchild, signal.SIGKILL)  # tidy up after the demo
    proc.communicate()


def compliant() -> None:
    proc = subprocess.Popen([sys.executable, "-c", PARENT_OF_SLEEPER],
                            stdout=subprocess.PIPE, text=True, start_new_session=True)
    proc.stdout.readline()
    try:
        proc.communicate(timeout=0.3)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)  # child and grandchild share the new group
        out, _ = proc.communicate(timeout=5)  # EOF: no process holds the pipe any more
        print(f"compliant:    process group killed (returncode {proc.returncode})")
        print(f"compliant:    communicate() returned {out!r}: every writer has exited")


def main() -> None:
    baseline()
    noncompliant()
    compliant()


if __name__ == "__main__":
    main()

# Output:
# run(timeout=0.3) on a single process -> TimeoutExpired after 0.3s, child killed
# noncompliant: child killed (returncode -9)
# noncompliant: communicate() still blocked: the grandchild holds the pipe
# noncompliant: grandchild still running: True
# compliant:    process group killed (returncode -9)
# compliant:    communicate() returned '': every writer has exited
