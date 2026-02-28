"""Bound your concurrency — `gather` over 500 URLs opens 500 connections

https://docs.python.org/3/library/asyncio-sync.html#asyncio.Semaphore

"Fetch all of these concurrently" produces
`await asyncio.gather(*(fetch(u) for u in urls))`. With ten URLs in the test
that is fine. With the real list it starts every request at once: the API
answers 429, the database runs out of connections, or the process hits its
file-descriptor limit. Nothing in the code says how many is too many.

Wrap the critical section in `async with semaphore:` so at most N run at once
while the rest wait their turn. Prefer `BoundedSemaphore`: an extra
`release()` (a bug in hand-written acquire/release code) raises instead of
silently raising the limit. A fixed pool of N workers reading from an
`asyncio.Queue` is the other standard shape. Counts below, not timings.
"""

import asyncio


class Upstream:
    """Rejects requests beyond 8 concurrent with HTTP 429."""

    LIMIT = 8

    def __init__(self) -> None:
        self.in_flight = 0
        self.peak = 0
        self.rejected = 0

    async def get(self, n: int) -> int:
        if self.in_flight >= self.LIMIT:
            self.rejected += 1
            return 429
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            for _ in range(3 + n % 4):  # a few IO waits of varying length
                await asyncio.sleep(0)
            return 200
        finally:
            self.in_flight -= 1


async def noncompliant(upstream: Upstream, urls: range) -> list[int]:
    return await asyncio.gather(*(upstream.get(n) for n in urls))


async def compliant_semaphore(upstream: Upstream, urls: range, limit: int) -> list[int]:
    gate = asyncio.BoundedSemaphore(limit)

    async def one(n: int) -> int:
        async with gate:
            return await upstream.get(n)

    return await asyncio.gather(*(one(n) for n in urls))


async def compliant_workers(upstream: Upstream, urls: range, workers: int) -> list[int]:
    queue: asyncio.Queue[int] = asyncio.Queue()
    for n in urls:
        queue.put_nowait(n)
    results: dict[int, int] = {}

    async def worker() -> None:
        while not queue.empty():
            n = queue.get_nowait()
            results[n] = await upstream.get(n)

    async with asyncio.TaskGroup() as tg:
        for _ in range(workers):
            tg.create_task(worker())
    return [results[n] for n in urls]


def summary(name: str, upstream: Upstream, codes: list[int]) -> None:
    print(f"{name:<34} requests={len(codes)} ok={codes.count(200)} "
          f"429={codes.count(429)} peak in flight={upstream.peak}")


async def scenario() -> None:
    urls = range(500)
    up = Upstream()
    summary("noncompliant gather(all)", up, await noncompliant(up, urls))
    up = Upstream()
    summary("compliant BoundedSemaphore(8)", up, await compliant_semaphore(up, urls, 8))
    up = Upstream()
    summary("compliant 8 workers + Queue", up, await compliant_workers(up, urls, 8))

    plain, bounded = asyncio.Semaphore(2), asyncio.BoundedSemaphore(2)
    plain.release()  # one release too many
    admitted = 0
    while not plain.locked():
        await plain.acquire()
        admitted += 1
    print(f"\nSemaphore(2) after an extra release(): now admits {admitted} at once")
    try:
        bounded.release()
    except ValueError as exc:
        print(f"BoundedSemaphore(2) extra release():   ValueError: {exc}")


def main() -> None:
    asyncio.run(scenario())


if __name__ == "__main__":
    main()

# Output:
# noncompliant gather(all)           requests=500 ok=8 429=492 peak in flight=8
# compliant BoundedSemaphore(8)      requests=500 ok=500 429=0 peak in flight=8
# compliant 8 workers + Queue        requests=500 ok=500 429=0 peak in flight=8
#
# Semaphore(2) after an extra release(): now admits 3 at once
# BoundedSemaphore(2) extra release():   ValueError: BoundedSemaphore released too many times
