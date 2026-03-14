"""Bare ``except`` — the retry loop that Ctrl-C cannot stop

"Make it robust, retry on any error" is often written as
``try: ... except: retry``. A bare ``except:`` (and ``except BaseException:``) catches everything, including
``KeyboardInterrupt`` from Ctrl-C, ``SystemExit`` from ``sys.exit()`` deep in a
helper, and ``GeneratorExit``. The operator presses Ctrl-C, the loop logs
"error, retrying" and keeps going; a worker that was told to exit never does.

Review note: catch the exceptions you expect (``OSError``, ``TimeoutError``,
a client library's error class), or at most ``Exception``, and log them with
the type. If you truly need a catch-all for cleanup, use ``finally`` or
re-raise with a bare ``raise``. Linters flag this as E722 / BLE001.
"""

import sys


class Job:
    """Fails twice with a network error, then the operator hits Ctrl-C."""

    def __init__(self, interrupt: type[BaseException]):
        self.calls = 0
        self.interrupt = interrupt

    def run(self) -> str:
        self.calls += 1
        if self.calls <= 2:
            raise ConnectionError("upstream reset")
        if self.calls == 3:
            if self.interrupt is SystemExit:
                sys.exit(3)
            raise self.interrupt()
        return "done"


def run_with_retry_noncompliant(job: Job, attempts: int = 5) -> str:
    for _ in range(attempts):
        try:
            return job.run()
        except:  # noqa: E722
            print("  noncompliant: error, retrying")
    return "gave up"


def run_with_retry_compliant(job: Job, attempts: int = 5) -> str:
    for _ in range(attempts):
        try:
            return job.run()
        except (ConnectionError, TimeoutError) as exc:
            print(f"  compliant: {type(exc).__name__}: {exc}, retrying")
    return "gave up"


def main() -> None:
    for interrupt in (KeyboardInterrupt, SystemExit):
        print(f"{interrupt.__name__} on the third call:")
        job = Job(interrupt)
        print("  noncompliant result:", run_with_retry_noncompliant(job), f"after {job.calls} calls")

        job = Job(interrupt)
        try:
            run_with_retry_compliant(job)
        except BaseException as exc:  # demo only: show what escaped
            print(f"  compliant: {type(exc).__name__} propagated after {job.calls} calls")

    print("hierarchy: KeyboardInterrupt is Exception?", issubclass(KeyboardInterrupt, Exception),
          " SystemExit is Exception?", issubclass(SystemExit, Exception))


if __name__ == "__main__":
    main()

# Output:
# KeyboardInterrupt on the third call:
#   noncompliant: error, retrying
#   noncompliant: error, retrying
#   noncompliant: error, retrying
#   noncompliant result: done after 4 calls
#   compliant: ConnectionError: upstream reset, retrying
#   compliant: ConnectionError: upstream reset, retrying
#   compliant: KeyboardInterrupt propagated after 3 calls
# SystemExit on the third call:
#   noncompliant: error, retrying
#   noncompliant: error, retrying
#   noncompliant: error, retrying
#   noncompliant result: done after 4 calls
#   compliant: ConnectionError: upstream reset, retrying
#   compliant: ConnectionError: upstream reset, retrying
#   compliant: SystemExit propagated after 3 calls
# hierarchy: KeyboardInterrupt is Exception? False  SystemExit is Exception? False
