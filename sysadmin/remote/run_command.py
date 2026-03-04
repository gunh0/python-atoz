"""subprocess.run for admin scripts — timeout, check, capture and exit codes

Most remote and local admin work ends in "run this command and decide what
happened": ssh, rsync, systemctl, ipmitool. subprocess.run() does it in one
call, but the defaults are wrong for unattended scripts: no timeout (a hung
ssh blocks cron forever), output not captured, and a failing command is not
an error unless you ask for check=True. The wrapper below always passes an
argument list (no shell), a timeout and capture_output, and turns every
outcome into one result with a status a caller can switch on.

Details that bite in practice, all shown below:
- A command killed by a signal has a negative returncode (-15 = SIGTERM);
  the same death seen through `sh -c` is 128 + 15 = 143.
- TimeoutExpired.stdout holds what was read before the kill, and it is
  bytes even with text=True.
- A missing executable is FileNotFoundError from run() itself, not an exit
  code 127 as it would be in a shell.
"""

import signal
import subprocess
import sys
from dataclasses import dataclass

PY = sys.executable  # child commands are small Python programs, so this runs anywhere


@dataclass
class Outcome:
    status: str  # ok | failed | signal | timeout | not-found
    code: int | None
    stdout: str
    stderr: str


def run(cmd: list[str], timeout: float = 5.0, input: str | None = None) -> Outcome:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              input=input, check=True)
    except FileNotFoundError:
        return Outcome("not-found", None, "", f"{cmd[0]}: command not found")
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return Outcome("timeout", None, partial, f"killed after {exc.timeout}s")
    except subprocess.CalledProcessError as exc:
        status = "signal" if exc.returncode < 0 else "failed"
        return Outcome(status, exc.returncode, exc.stdout, exc.stderr)
    return Outcome("ok", proc.returncode, proc.stdout, proc.stderr)


def show(label: str, outcome: Outcome) -> None:
    code = "-" if outcome.code is None else outcome.code
    extra = ""
    if outcome.status == "signal":
        extra = f" ({signal.Signals(-outcome.code).name})"
    elif outcome.code is not None and outcome.code > 128:
        extra = f" (128 + {signal.Signals(outcome.code - 128).name})"
    print(f"{label:<24} status={outcome.status:<9} code={code}{extra}")
    for name in ("stdout", "stderr"):
        text = getattr(outcome, name).strip()
        if text:
            print(f"{'':<24} {name}: {text.replace(chr(10), ' | ')}")


def main() -> None:
    show("success", run([PY, "-c", "print('active (running)')"]))
    show("inactive, exit 3", run([PY, "-c", "import sys; print('inactive (dead)'); sys.exit(3)"]))
    show("sys.exit(message)", run([PY, "-c", "import sys; sys.exit('unit app.service not found')"]))
    show("stdin -> stdout", run([PY, "-c", "import sys; print(sorted(sys.stdin.read().split()))"],
                                input="web-02 db-01 web-01\n"))
    show("killed by SIGTERM", run([PY, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"]))
    # exec 2>/dev/null silences the shell's own "Terminated" notice (it contains a PID)
    show("same, through sh -c", run(["sh", "-c", 'exec 2>/dev/null; "$0" -c "import os, signal; '
                                     'os.kill(os.getpid(), signal.SIGTERM)"; exit $?', PY]))
    show("hung, timeout", run([PY, "-c", "import time; print('step 1 done', flush=True); time.sleep(30)"],
                              timeout=1.0))
    show("missing command", run(["no-such-tool", "--version"]))

    try:
        subprocess.run([PY, "-c", "import time; print('partial', flush=True); time.sleep(30)"],
                       capture_output=True, text=True, timeout=1.0)
    except subprocess.TimeoutExpired as exc:
        print(f"TimeoutExpired.stdout despite text=True: {exc.stdout!r}")
    exc = subprocess.CalledProcessError(2, ["rsync", "-a", "src/", "dst/"])
    print("check=True error message:", exc)


if __name__ == "__main__":
    main()

# Output:
# success                  status=ok        code=0
#                          stdout: active (running)
# inactive, exit 3         status=failed    code=3
#                          stdout: inactive (dead)
# sys.exit(message)        status=failed    code=1
#                          stderr: unit app.service not found
# stdin -> stdout          status=ok        code=0
#                          stdout: ['db-01', 'web-01', 'web-02']
# killed by SIGTERM        status=signal    code=-15 (SIGTERM)
# same, through sh -c      status=failed    code=143 (128 + SIGTERM)
# hung, timeout            status=timeout   code=-
#                          stdout: step 1 done
#                          stderr: killed after 1.0s
# missing command          status=not-found code=-
#                          stderr: no-such-tool: command not found
# TimeoutExpired.stdout despite text=True: b'partial\n'
# check=True error message: Command '['rsync', '-a', 'src/', 'dst/']' returned non-zero exit status 2.
