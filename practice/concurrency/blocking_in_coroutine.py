"""A blocking call inside `async def` freezes every other coroutine

https://docs.python.org/3/library/asyncio-dev.html#running-blocking-code

`async def` is not magic. When a handler is converted to asyncio it
often keeps `time.sleep()`, `requests.get()`, a synchronous DB driver or a big
`hashlib` loop inside the coroutine. It still returns the right answer, so the
tests pass — but while that call runs, the event loop cannot switch to any
other task: health checks, other requests and timeouts all stall.

The fix is to await something that actually yields: the async version of the
API, or `await asyncio.to_thread(blocking_fn, ...)` for blocking IO (a process
pool for CPU-heavy work). The demo makes the stall visible without timings:
the blocking call waits on an Event that only the *other* coroutine can set,
and asyncio's debug mode reports the slow step through the `asyncio` logger.
"""

import asyncio
import logging
import threading


def blocking_fetch(ready: threading.Event, wait: float) -> bool:
    """Stands in for requests.get(): blocks the calling thread."""
    return ready.wait(timeout=wait)  # True if other work set the event meanwhile


async def heartbeat(ready: threading.Event, log: list[str]) -> None:
    log.append("heartbeat ran")
    ready.set()


async def handler_noncompliant(ready: threading.Event, log: list[str]) -> None:
    log.append("handler: start fetch")
    other_work = blocking_fetch(ready, 0.3)
    log.append(f"handler: fetch done, loop ran meanwhile={other_work}")


async def handler_compliant(ready: threading.Event, log: list[str]) -> None:
    log.append("handler: start fetch")
    other_work = await asyncio.to_thread(blocking_fetch, ready, 5.0)
    log.append(f"handler: fetch done, loop ran meanwhile={other_work}")


class SlowStepCounter(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.slow = 0

    def emit(self, record: logging.LogRecord) -> None:
        if record.getMessage().startswith("Executing"):  # "Executing <Task ...> took N seconds"
            self.slow += 1


def run(handler) -> tuple[list[str], int]:
    log: list[str] = []
    counter = SlowStepCounter()
    asyncio_logger = logging.getLogger("asyncio")
    asyncio_logger.addHandler(counter)
    asyncio_logger.propagate = False  # keep the timing text off stderr

    async def scenario() -> None:
        ready = threading.Event()
        async with asyncio.TaskGroup() as tg:
            tg.create_task(handler(ready, log))  # scheduled first
            tg.create_task(heartbeat(ready, log))

    try:
        asyncio.run(scenario(), debug=True)  # debug: warn on steps > 0.1 s
    finally:
        asyncio_logger.removeHandler(counter)
    return log, counter.slow


def main() -> None:
    for name, handler in (("noncompliant", handler_noncompliant), ("compliant", handler_compliant)):
        log, slow = run(handler)
        print(f"{name}:")
        for line in log:
            print(f"  {line}")
        print(f"  asyncio debug: {slow} slow step(s) reported")


if __name__ == "__main__":
    main()

# Output:
# noncompliant:
#   handler: start fetch
#   handler: fetch done, loop ran meanwhile=False
#   heartbeat ran
#   asyncio debug: 1 slow step(s) reported
# compliant:
#   handler: start fetch
#   heartbeat ran
#   handler: fetch done, loop ran meanwhile=True
#   asyncio debug: 0 slow step(s) reported
