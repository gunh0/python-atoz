"""Cancellation and `asyncio.timeout` — never swallow CancelledError

https://docs.python.org/3/library/asyncio-task.html#task-cancellation

Timeouts in asyncio work by *cancelling* the task: `asyncio.timeout()` throws
CancelledError into the awaiting coroutine and converts it to TimeoutError
when the block exits. It is easy to "handle shutdown gracefully" with
`except asyncio.CancelledError: return None` or a catch-all
`except BaseException`. That looks defensive and quietly breaks both
mechanisms: the timeout block exits normally as if the call succeeded, and
`task.cancel()` no longer stops the task — `task.cancelled()` stays False.

Do cleanup in `finally` (or catch, clean up, and re-raise), and let the
CancelledError propagate. The caller decides what a timeout means.
"""

import asyncio


class Pool:
    def __init__(self) -> None:
        self.in_use = 0


async def slow_upstream() -> str:
    await asyncio.sleep(10)  # far longer than any deadline below
    return "payload"


async def fetch_noncompliant(pool: Pool) -> str | None:
    pool.in_use += 1
    try:
        return await slow_upstream()
    except asyncio.CancelledError:
        return None  # "graceful": the cancellation is swallowed here
    finally:
        pool.in_use -= 1


async def fetch_compliant(pool: Pool) -> str:
    pool.in_use += 1
    try:
        return await slow_upstream()
    finally:
        pool.in_use -= 1  # cleanup runs, CancelledError keeps going


async def with_deadline(fetch, pool: Pool) -> str:
    try:
        async with asyncio.timeout(0.05):
            result = await fetch(pool)
        return f"returned {result!r} as if it succeeded"
    except TimeoutError:
        return "TimeoutError raised, caller can retry or fail"


async def cancel_from_outside(fetch, pool: Pool) -> str:
    task = asyncio.create_task(fetch(pool))
    await asyncio.sleep(0)  # let it start
    task.cancel()
    try:
        result = await task
        return f"task finished normally with {result!r}, cancelled()={task.cancelled()}"
    except asyncio.CancelledError:
        return f"task stopped, cancelled()={task.cancelled()}"


async def scenario() -> None:
    for name, fetch in (("noncompliant", fetch_noncompliant), ("compliant", fetch_compliant)):
        pool = Pool()
        print(f"{name + ':':<14}timeout -> {await with_deadline(fetch, pool)}")
        print(f"{'':<14}cancel  -> {await cancel_from_outside(fetch, pool)}")
        print(f"{'':<14}pool connections still in use: {pool.in_use}")


def main() -> None:
    asyncio.run(scenario())


if __name__ == "__main__":
    main()

# Output:
# noncompliant: timeout -> returned None as if it succeeded
#               cancel  -> task finished normally with None, cancelled()=False
#               pool connections still in use: 0
# compliant:    timeout -> TimeoutError raised, caller can retry or fail
#               cancel  -> task stopped, cancelled()=True
#               pool connections still in use: 0
