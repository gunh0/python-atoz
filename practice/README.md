# practice — what looks right in review and is not

Things I keep catching in code review, in other people's code and in my own: code that reads fine, passes a quick test, and still does the wrong thing. Each example shows the common way to write it, what actually happens, the fix, and what I look for when reviewing.

```bash
python3 practice/<topic>/<example>.py      # every example runs on its own
python3 scripts/check.py practice          # run all and compare with the # Output: blocks
```

26 examples, checked on Python 3.13, Python 3.14.

## pitfalls

Language behaviour that surprises: defaults, closures, identity, rounding, exceptions, attributes and hashing.

| Example | Notes |
| --- | --- |
| [`deferred_annotations.py`](pitfalls/deferred_annotations.py) | Deferred annotations (PEP 649/749) — ``cls.__dict__["__annotations__"]`` is gone in 3.14 |
| [`except_without_parentheses.py`](pitfalls/except_without_parentheses.py) | ``except A, B:`` without parentheses (PEP 758) — and the Python 2 ghost it revives |
| [`is_vs_equality.py`](pitfalls/is_vs_equality.py) | ``is`` vs ``==`` — identity only looks like equality for small ints and interned strings |
| [`late_binding_closures.py`](pitfalls/late_binding_closures.py) | Late-binding closures — lambdas in a loop all see the last value |
| [`mutable_default_argument.py`](pitfalls/mutable_default_argument.py) | Mutable default arguments — the default is evaluated once, not per call |

## data

Numbers, money, dates and time zones, text encodings, Unicode, JSON and CSV.

| Example | Notes |
| --- | --- |
| [`bankers_rounding.py`](data/bankers_rounding.py) | Banker's rounding — ``round(2.5)`` is 2, and ``round(2.675, 2)`` is 2.67 |
| [`bytes_and_encodings.py`](data/bytes_and_encodings.py) | str vs bytes and encodings — errors=, BOMs, and byte limits |
| [`decimal_money.py`](data/decimal_money.py) | Decimal for money — and why ``Decimal(0.1)`` is not ``Decimal("0.1")`` |
| [`dst_transitions_zoneinfo.py`](data/dst_transitions_zoneinfo.py) | DST transitions with zoneinfo — "one day later" is not always 24 hours |
| [`float_equality.py`](data/float_equality.py) | Float equality — ``0.1 + 0.2 == 0.3`` is False, and summing order matters |
| [`floor_division_negatives.py`](data/floor_division_negatives.py) | Floor division and modulo with negatives — Python floors, C/Java/JS truncate |
| [`naive_vs_aware_datetime.py`](data/naive_vs_aware_datetime.py) | Naive vs aware datetimes — a timestamp without a zone means "whatever this machine thinks" |
| [`unicode_normalization_casefold.py`](data/unicode_normalization_casefold.py) | Unicode normalization and casefold — equal-looking strings that are not ``==`` |
| [`utcnow_deprecated.py`](data/utcnow_deprecated.py) | ``datetime.utcnow()`` — deprecated since 3.12, and naive in a way that bites |

## concurrency

Threads, processes and asyncio: races, blocking calls, cancellation, timeouts and limits.

| Example | Notes |
| --- | --- |
| [`blocking_in_coroutine.py`](concurrency/blocking_in_coroutine.py) | A blocking call inside `async def` freezes every other coroutine |
| [`cancellation_timeout.py`](concurrency/cancellation_timeout.py) | Cancellation and `asyncio.timeout` — never swallow CancelledError |
| [`gather_vs_taskgroup.py`](concurrency/gather_vs_taskgroup.py) | `asyncio.gather` vs `asyncio.TaskGroup` — what happens to the other tasks? |
| [`lost_update_race.py`](concurrency/lost_update_race.py) | Lost update: a read-modify-write race, forced to happen every time |
| [`threads_processes_asyncio.py`](concurrency/threads_processes_asyncio.py) | Threads, processes or asyncio? Count the work, do not trust a stopwatch |

## reliability

Retries, idempotency, circuit breakers, logging, configuration, dataclasses, tests and profiling.

| Example | Notes |
| --- | --- |
| [`circuit_breaker.py`](reliability/circuit_breaker.py) | Circuit breaker — stop hammering a dependency that is already down |
| [`config_from_env.py`](reliability/config_from_env.py) | Configuration from environment variables — parse once, validate, fail loudly |
| [`idempotency_keys.py`](reliability/idempotency_keys.py) | Idempotency keys — retries are safe only if the server can recognise them |
| [`logging_dictconfig.py`](reliability/logging_dictconfig.py) | logging.config.dictConfig — and why every line shows up twice |
| [`retry_backoff.py`](reliability/retry_backoff.py) | Retries with exponential backoff and jitter — and a clock you can inject |
| [`structured_json_logs.py`](reliability/structured_json_logs.py) | Structured JSON logs — one event per line, fields instead of f-strings |

## review

Small tools I use when reviewing: an AST-based code reviewer and a dependency name check.

| Example | Notes |
| --- | --- |
| [`code_reviewer.py`](review/code_reviewer.py) | Code reviewer v2 — add rules for shell=True and bare `except:` |
