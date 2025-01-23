"""Threads, processes or asyncio? Count the work, do not trust a stopwatch

https://docs.python.org/3/library/concurrency.html

The usual reflex is `ThreadPoolExecutor` for everything ("make it faster") or
`asyncio` because it sounds modern. The choice depends on where the time goes:
waiting on IO overlaps fine in threads and in asyncio, but on a standard
(GIL) CPython build only one thread executes Python bytecode at a time, so
CPU-bound work in threads or coroutines is still serial. Processes give real
CPU parallelism but cost start-up and pickling, and they do not share memory.

The model below counts scheduler ticks instead of wall time so the result is
the same on every machine; the second half proves the memory-sharing facts
with real threads, processes and coroutines. (Free-threaded 3.13t/3.14t
builds change the CPU row for threads — check `sys._is_gil_enabled()`.)
"""

import asyncio
import os
import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

# A job is a list of steps: ("cpu", n) needs an execution lane for n ticks,
# ("io", n) just waits n ticks and needs no lane.
IO_JOB = [("cpu", 1), ("io", 10), ("cpu", 1)]
CPU_JOB = [("cpu", 10)]


def simulate(jobs: list[list[tuple[str, int]]], lanes: int, startup: int = 0) -> int:
    """Tick-by-tick scheduler: `lanes` jobs may run CPU steps at once."""
    steps = [list(job) for job in jobs]
    ticks = startup
    while any(steps):
        running = 0
        for job in steps:
            if not job:
                continue
            kind, left = job[0]
            if kind == "cpu":
                if running == lanes:
                    continue
                running += 1
            job[0] = (kind, left - 1)
            if left - 1 == 0:
                job.pop(0)
        ticks += 1
    return ticks


def model() -> None:
    workloads = {"8 io-bound jobs": [IO_JOB] * 8, "8 cpu-bound jobs": [CPU_JOB] * 8}
    print(f"{'ticks to finish':<18}{'sequential':>11}{'threads':>9}{'asyncio':>9}{'4 procs':>9}")
    for name, jobs in workloads.items():
        sequential = sum(n for job in jobs for _, n in job)
        threads = simulate(jobs, lanes=1)      # GIL: one bytecode lane
        coroutines = simulate(jobs, lanes=1)   # one thread, one lane
        procs = simulate(jobs, lanes=4, startup=3)  # 3 ticks to spawn + pickle
        print(f"{name:<18}{sequential:>11}{threads:>9}{coroutines:>9}{procs:>9}")


SHARED: list[str] = []


def record(tag: str) -> int:
    SHARED.append(tag)
    return os.getpid()


async def record_async(tag: str, in_flight: list[int], peak: list[int]) -> None:
    in_flight[0] += 1
    peak[0] = max(peak[0], in_flight[0])
    await asyncio.sleep(0)  # an IO wait: yields to the other coroutines
    SHARED.append(tag)
    in_flight[0] -= 1


def facts() -> None:
    parent = os.getpid()

    SHARED.clear()
    barrier = threading.Barrier(4, timeout=5)

    def io_like(i: int) -> int:
        barrier.wait()  # only returns once all 4 are blocked at the same time
        return record(f"t{i}")

    with ThreadPoolExecutor(max_workers=4) as pool:
        pids = list(pool.map(io_like, range(4)))
    print(f"threads:   4 waits overlapped (barrier passed), "
          f"same process={all(p == parent for p in pids)}, parent sees {len(SHARED)} appends")

    SHARED.clear()
    with ProcessPoolExecutor(max_workers=2) as pool:
        pids = list(pool.map(record, ["p0", "p1", "p2", "p3"]))
    print(f"processes: 4 results returned by pickling, "
          f"other process={all(p != parent for p in pids)}, parent sees {len(SHARED)} appends")

    SHARED.clear()
    in_flight, peak = [0], [0]

    async def run() -> None:
        await asyncio.gather(*(record_async(f"a{i}", in_flight, peak) for i in range(4)))

    asyncio.run(run())
    print(f"asyncio:   peak in flight={peak[0]}, one thread, parent sees {len(SHARED)} appends")


def main() -> None:
    model()
    print()
    facts()


if __name__ == "__main__":
    main()

# Output:
# ticks to finish    sequential  threads  asyncio  4 procs
# 8 io-bound jobs            96       19       19       16
# 8 cpu-bound jobs           80       80       80       23
#
# threads:   4 waits overlapped (barrier passed), same process=True, parent sees 4 appends
# processes: 4 results returned by pickling, other process=True, parent sees 0 appends
# asyncio:   peak in flight=4, one thread, parent sees 4 appends
