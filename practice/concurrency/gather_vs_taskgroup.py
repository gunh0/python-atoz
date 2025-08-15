"""`asyncio.gather` vs `asyncio.TaskGroup` — what happens to the other tasks?

https://docs.python.org/3/library/asyncio-task.html#task-groups

Most asyncio code fans out with `await asyncio.gather(*coros)`. When
one coroutine raises, gather re-raises that first exception to the caller —
and leaves the siblings running. Nobody awaits them any more: they keep
writing to the database after the request already failed, and their own
exceptions end up as "Task exception was never retrieved". The common "fix",
`return_exceptions=True`, turns errors into list items that the next line of
code forgets to check.

`TaskGroup` (3.11+) gives structured concurrency: the first failure cancels
the siblings, the `async with` block does not exit until every task has
finished, and all failures arrive together as an ExceptionGroup for
`except*`. Steps below are `await asyncio.sleep(0)` so the order is exact.
"""

import asyncio


async def job(name: str, steps: int, log: list[str], fail: bool = False) -> str:
    try:
        for _ in range(steps):
            await asyncio.sleep(0)
        if fail:
            raise ConnectionError(f"{name} failed")
        log.append(f"{name} finished")
        return name
    except asyncio.CancelledError:
        log.append(f"{name} cancelled")
        raise


async def settle() -> None:
    for _ in range(10):  # let any orphaned tasks run to completion
        await asyncio.sleep(0)


async def with_gather(log: list[str]) -> None:
    try:
        await asyncio.gather(job("a", 1, log, fail=True), job("b", 3, log), job("c", 5, log))
    except ConnectionError as exc:
        log.append(f"caller caught {exc!r}, returns error to client")
    await settle()


async def with_return_exceptions(log: list[str]) -> None:
    results = await asyncio.gather(job("a", 1, log, fail=True), job("b", 3, log),
                                   return_exceptions=True)
    log.append(f"results = {results!r}")
    log.append(f"next line: ', '.join(results) -> "
               f"{'TypeError' if any(isinstance(r, BaseException) for r in results) else 'ok'}")


async def with_taskgroup(log: list[str]) -> None:
    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(job("a", 1, log, fail=True))
            tg.create_task(job("b", 3, log))
            tg.create_task(job("c", 5, log))
        log.append("not reached")
    except* ConnectionError as group:
        log.append(f"caller caught {group!r}")
    await settle()


async def with_taskgroup_two_failures(log: list[str]) -> None:
    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(job("a", 1, log, fail=True))
            tg.create_task(job("b", 1, log, fail=True))
            tg.create_task(job("c", 5, log))
    except* ConnectionError as group:
        log.append(f"caller caught {len(group.exceptions)} errors: "
                   f"{sorted(str(e) for e in group.exceptions)}")


def main() -> None:
    scenarios = [
        ("noncompliant gather", with_gather),
        ("noncompliant gather(return_exceptions=True)", with_return_exceptions),
        ("compliant TaskGroup", with_taskgroup),
        ("compliant TaskGroup, two failures", with_taskgroup_two_failures),
    ]
    for title, scenario in scenarios:
        log: list[str] = []
        asyncio.run(scenario(log))
        print(f"{title}:")
        for line in log:
            print(f"  {line}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant gather:
#   caller caught ConnectionError('a failed'), returns error to client
#   b finished
#   c finished
# noncompliant gather(return_exceptions=True):
#   b finished
#   results = [ConnectionError('a failed'), 'b']
#   next line: ', '.join(results) -> TypeError
# compliant TaskGroup:
#   b cancelled
#   c cancelled
#   caller caught ExceptionGroup('unhandled errors in a TaskGroup', [ConnectionError('a failed')])
# compliant TaskGroup, two failures:
#   c cancelled
#   caller caught 2 errors: ['a failed', 'b failed']
