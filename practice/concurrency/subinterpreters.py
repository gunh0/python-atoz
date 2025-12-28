# requires-python: >=3.14
"""Python 3.14 subinterpreters — one process, one GIL per interpreter

https://peps.python.org/pep-0734/

`concurrent.interpreters` (PEP 734) and `InterpreterPoolExecutor` run Python
code in several interpreters inside one process. Each interpreter has its own
GIL, so CPU-bound work runs in parallel like processes, with cheaper start-up
and no fork. It is tempting to swap `ThreadPoolExecutor` for
`InterpreterPoolExecutor` and call it done; the code then trips over the
isolation rules, which are closer to multiprocessing than to threads:

  * module globals are per interpreter — a counter updated in a worker never
    changes in the main interpreter (and this module is imported again in
    each worker, so keep side effects under `if __name__ == "__main__"`);
  * an exception in a worker arrives as `ExecutionFailed`, so
    `except ValueError` around `interp.call()` catches nothing;
  * only shareable objects cross directly (bytes, str, int, tuples of them,
    Queues); lists and locks raise NotShareableError.

Pass immutable inputs, return results, use an interpreters Queue for streams,
and always close the interpreters you create.
"""

import hashlib
from concurrent import interpreters
from concurrent.futures import InterpreterPoolExecutor

PROCESSED = 0  # per-interpreter state, as the demo shows


def digest_chain(seed: bytes, rounds: int = 20_000) -> str:
    """CPU-bound: repeated SHA-256, the kind of work threads cannot parallelise."""
    global PROCESSED
    PROCESSED += 1
    h = seed
    for _ in range(rounds):
        h = hashlib.sha256(h).digest()
    return h.hex()[:16]


def processed() -> int:
    return PROCESSED


def parse_quota(text: str) -> int:
    return int(text)


def main() -> None:
    interp = interpreters.create()
    try:
        first = interp.call(digest_chain, b"job-1")
        interp.call(digest_chain, b"job-2")
        print(f"worker result {first}: worker PROCESSED={interp.call(processed)}, "
              f"main PROCESSED={PROCESSED}")

        try:
            interp.call(parse_quota, "12a")
        except ValueError:
            print("noncompliant: except ValueError caught it")
        except interpreters.ExecutionFailed as exc:
            print(f"noncompliant: except ValueError missed it; got ExecutionFailed "
                  f"wrapping {exc.excinfo.type.__name__}: {exc.excinfo.msg}")

        for label, value in (("list [1, 2]", [1, 2]), ("tuple (1, 2)", (1, 2)), ("bytes", b"x")):
            print(f"is_shareable({label}) = {interpreters.is_shareable(value)}")
        try:
            interp.prepare_main(batch=[b"a", b"b"])
        except interpreters.NotShareableError:
            print("noncompliant: prepare_main(batch=[...]) -> NotShareableError")

        queue = interpreters.create_queue()
        interp.prepare_main(results=queue, batch=(b"a", b"b", b"c"))
        interp.exec("import hashlib\n"
                    "for item in batch:\n"
                    "    results.put((item, hashlib.sha256(item).hexdigest()[:8]))\n")
        streamed = [queue.get() for _ in range(3)]
        print(f"compliant: tuple in, Queue out -> {streamed}")
    finally:
        interp.close()

    seeds = [f"job-{i}".encode() for i in range(4)]
    with InterpreterPoolExecutor(max_workers=4) as pool:
        parallel = list(pool.map(digest_chain, seeds))
    serial = [digest_chain(seed) for seed in seeds]
    print(f"compliant: InterpreterPoolExecutor x4 == serial results: {parallel == serial}")
    print(f"compliant: main PROCESSED={PROCESSED} (only the serial run counted here)")


if __name__ == "__main__":
    main()

# Output:
# worker result 6b5f89801c0d1666: worker PROCESSED=2, main PROCESSED=0
# noncompliant: except ValueError missed it; got ExecutionFailed wrapping ValueError: invalid literal for int() with base 10: '12a'
# is_shareable(list [1, 2]) = False
# is_shareable(tuple (1, 2)) = True
# is_shareable(bytes) = True
# noncompliant: prepare_main(batch=[...]) -> NotShareableError
# compliant: tuple in, Queue out -> [(b'a', 'ca978112'), (b'b', '3e23e816'), (b'c', '2e7d2c03')]
# compliant: InterpreterPoolExecutor x4 == serial results: True
# compliant: main PROCESSED=4 (only the serial run counted here)
