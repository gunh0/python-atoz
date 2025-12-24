# requires-python: >=3.14
"""Python 3.14 asyncio introspection — which task is waiting on what?

https://docs.python.org/3.14/library/asyncio-graph.html

An async service "sometimes hangs". Before 3.14 the usual tools were
`asyncio.all_tasks()`, which gives a flat list of task reprs, and guesswork.
Python 3.14 adds `asyncio.capture_call_graph()` and `print_call_graph()`,
which show each task's coroutine stack *and* which tasks are awaiting it, and
`python -m asyncio pstree <PID>` / `ps <PID>` to read the same graph from a
running process from the outside.

Below, two request handlers wait inside a TaskGroup on fetches that need a
lock, and the lock holder waits forever on a token refresh that nobody
triggers — a classic deadlock. The flat list says "7 pending
tasks"; the graph names the culprit. `format_call_graph()` prints file paths
and object ids, so this demo renders the same data with names and line
numbers of this file only.
"""

import asyncio

token_ready = asyncio.Event()  # the refresh that should set this was never scheduled
cache_lock = asyncio.Lock()


async def refresh_token() -> None:
    async with cache_lock:
        await token_ready.wait()


async def fetch(item: str) -> str:
    async with cache_lock:
        return item


async def handler(request: str) -> None:
    async with asyncio.TaskGroup() as tg:
        tg.create_task(fetch(f"{request}/a"), name=f"fetch {request}/a")
        tg.create_task(fetch(f"{request}/b"), name=f"fetch {request}/b")


def frames_here(graph: asyncio.FutureCallGraph) -> str:
    """Innermost asyncio primitive, then this file's coroutines with line numbers."""
    parts = []
    for entry in graph.call_stack:
        code = entry.frame.f_code
        if code.co_filename == __file__:
            parts.append(f"{code.co_qualname}():{entry.frame.f_lineno}")
        elif not parts and code.co_qualname.split(".")[0] in {"Lock", "Event"}:
            parts.append(f"[{code.co_qualname}]")
    return " <- ".join(parts)


def render(tasks: set[asyncio.Task]) -> list[str]:
    graphs = {t: asyncio.capture_call_graph(t) for t in tasks}
    children: dict[asyncio.Future, list[asyncio.Task]] = {}
    roots = []
    for task, graph in graphs.items():
        if graph.awaited_by:
            for parent in graph.awaited_by:
                children.setdefault(parent.future, []).append(task)
        else:
            roots.append(task)

    lines: list[str] = []

    def walk(task: asyncio.Task, depth: int) -> None:
        lines.append(f"{'  ' * depth + task.get_name():<16} {frames_here(graphs[task])}")
        for child in sorted(children.get(task, []), key=asyncio.Task.get_name):
            walk(child, depth + 1)

    for root in sorted(roots, key=asyncio.Task.get_name):
        walk(root, 0)
    return lines


async def main_async() -> None:
    tasks = [asyncio.create_task(refresh_token(), name="refresh-token")]
    tasks += [asyncio.create_task(handler(r), name=f"handler {r}") for r in ("r1", "r2")]
    for _ in range(5):
        await asyncio.sleep(0)  # let everything reach its await

    others = asyncio.all_tasks() - {asyncio.current_task()}
    print(f"all_tasks(): {len(others)} pending: {sorted(t.get_name() for t in others)}")
    print("capture_call_graph():")
    for line in render(others):
        print(f"  {line}")
    holders = [t.get_name() for t in others
               if "[Event.wait]" in frames_here(asyncio.capture_call_graph(t))]
    print(f"lock holder waiting on an Event: {holders}")

    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()

# Output:
# all_tasks(): 7 pending: ['fetch r1/a', 'fetch r1/b', 'fetch r2/a', 'fetch r2/b', 'handler r1', 'handler r2', 'refresh-token']
# capture_call_graph():
#   handler r1       handler():38
#     fetch r1/a     [Lock.acquire] <- fetch():33
#     fetch r1/b     [Lock.acquire] <- fetch():33
#   handler r2       handler():38
#     fetch r2/a     [Lock.acquire] <- fetch():33
#     fetch r2/b     [Lock.acquire] <- fetch():33
#   refresh-token    [Event.wait] <- refresh_token():29
# lock holder waiting on an Event: ['refresh-token']
