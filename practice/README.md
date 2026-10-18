# practice — what looks right in review and is not

Things I keep catching in code review, in other people's code and in my own: code that reads fine, passes a quick test, and still does the wrong thing. Each example shows the common way to write it, what actually happens, the fix, and what I look for when reviewing.

```bash
python3 practice/<topic>/<example>.py      # every example runs on its own
python3 scripts/check.py practice          # run all and compare with the # Output: blocks
```

52 examples, checked on Python 3.13, Python 3.14, Python 3.15.

## pitfalls

Language behaviour that surprises: defaults, closures, identity, rounding, exceptions, attributes and hashing.

| Example | Notes |
| --- | --- |
| [`bare_except.py`](pitfalls/bare_except.py) | Bare ``except`` — the retry loop that Ctrl-C cannot stop |
| [`class_vs_instance_attributes.py`](pitfalls/class_vs_instance_attributes.py) | Class vs instance attributes — a list on the class is shared by every instance |
| [`copy_vs_deepcopy.py`](pitfalls/copy_vs_deepcopy.py) | copy vs deepcopy — ``dict(base)`` copies the top level only |
| [`deferred_annotations.py`](pitfalls/deferred_annotations.py) | Deferred annotations (PEP 649/749) — ``cls.__dict__["__annotations__"]`` is gone in 3.14 |
| [`eq_without_hash.py`](pitfalls/eq_without_hash.py) | ``__eq__`` without ``__hash__`` — unhashable objects, or worse, a hash that changes |
| [`except_without_parentheses.py`](pitfalls/except_without_parentheses.py) | ``except A, B:`` without parentheses (PEP 758) — and the Python 2 ghost it revives |
| [`exception_chaining.py`](pitfalls/exception_chaining.py) | Exception chaining — ``raise ... from err`` keeps the real cause |
| [`falsy_config_defaults.py`](pitfalls/falsy_config_defaults.py) | Truthiness in config defaults — ``value or default`` throws away 0, "" and [] |
| [`generator_exhaustion.py`](pitfalls/generator_exhaustion.py) | Generator exhaustion — the second pass over an iterator sees nothing |
| [`is_vs_equality.py`](pitfalls/is_vs_equality.py) | ``is`` vs ``==`` — identity only looks like equality for small ints and interned strings |
| [`late_binding_closures.py`](pitfalls/late_binding_closures.py) | Late-binding closures — lambdas in a loop all see the last value |
| [`mutable_default_argument.py`](pitfalls/mutable_default_argument.py) | Mutable default arguments — the default is evaluated once, not per call |
| [`mutate_list_while_iterating.py`](pitfalls/mutate_list_while_iterating.py) | Mutating a list while iterating — items get skipped without any error |
| [`return_in_finally.py`](pitfalls/return_in_finally.py) | ``return`` in ``finally`` — the exception just disappears |
| [`shadowing_builtins_and_modules.py`](pitfalls/shadowing_builtins_and_modules.py) | Shadowing builtins and stdlib modules — ``list = ...`` and a file named ``random.py`` |

## data

Numbers, money, dates and time zones, text encodings, Unicode, JSON and CSV.

| Example | Notes |
| --- | --- |
| [`bankers_rounding.py`](data/bankers_rounding.py) | Banker's rounding — ``round(2.5)`` is 2, and ``round(2.675, 2)`` is 2.67 |
| [`bytes_and_encodings.py`](data/bytes_and_encodings.py) | str vs bytes and encodings — errors=, BOMs, and byte limits |
| [`csv_quoting_formula_injection.py`](data/csv_quoting_formula_injection.py) | CSV quoting and formula injection — ``",".join(row)`` is not CSV |
| [`decimal_money.py`](data/decimal_money.py) | Decimal for money — and why ``Decimal(0.1)`` is not ``Decimal("0.1")`` |
| [`dst_transitions_zoneinfo.py`](data/dst_transitions_zoneinfo.py) | DST transitions with zoneinfo — "one day later" is not always 24 hours |
| [`float_equality.py`](data/float_equality.py) | Float equality — ``0.1 + 0.2 == 0.3`` is False, and summing order matters |
| [`floor_division_negatives.py`](data/floor_division_negatives.py) | Floor division and modulo with negatives — Python floors, C/Java/JS truncate |
| [`json_nan_decimal_bigint.py`](data/json_nan_decimal_bigint.py) | json with NaN, Decimal and big ints — valid for Python, broken for everyone else |
| [`naive_vs_aware_datetime.py`](data/naive_vs_aware_datetime.py) | Naive vs aware datetimes — a timestamp without a zone means "whatever this machine thinks" |
| [`sort_stability_and_keys.py`](data/sort_stability_and_keys.py) | Sort stability and keys — strings sort as text, ties keep input order |
| [`unicode_normalization_casefold.py`](data/unicode_normalization_casefold.py) | Unicode normalization and casefold — equal-looking strings that are not ``==`` |
| [`utcnow_deprecated.py`](data/utcnow_deprecated.py) | ``datetime.utcnow()`` — deprecated since 3.12, and naive in a way that bites |
| [`utf8_mode_default.py`](data/utf8_mode_default.py) | UTF-8 mode on by default (PEP 686, Python 3.15) — bare ``open()`` stops meaning "locale" |

## concurrency

Threads, processes and asyncio: races, blocking calls, cancellation, timeouts and limits.

| Example | Notes |
| --- | --- |
| [`asyncio_call_graph.py`](concurrency/asyncio_call_graph.py) | Python 3.14 asyncio introspection — which task is waiting on what? |
| [`blocking_in_coroutine.py`](concurrency/blocking_in_coroutine.py) | A blocking call inside `async def` freezes every other coroutine |
| [`cancellation_timeout.py`](concurrency/cancellation_timeout.py) | Cancellation and `asyncio.timeout` — never swallow CancelledError |
| [`gather_vs_taskgroup.py`](concurrency/gather_vs_taskgroup.py) | `asyncio.gather` vs `asyncio.TaskGroup` — what happens to the other tasks? |
| [`lost_update_race.py`](concurrency/lost_update_race.py) | Lost update: a read-modify-write race, forced to happen every time |
| [`semaphore_bound.py`](concurrency/semaphore_bound.py) | Bound your concurrency — `gather` over 500 URLs opens 500 connections |
| [`subinterpreters.py`](concurrency/subinterpreters.py) | Python 3.14 subinterpreters — one process, one GIL per interpreter |
| [`subprocess_timeout.py`](concurrency/subprocess_timeout.py) | Subprocess timeouts — kill the child, and the children it started |
| [`threads_processes_asyncio.py`](concurrency/threads_processes_asyncio.py) | Threads, processes or asyncio? Count the work, do not trust a stopwatch |

## reliability

Retries, idempotency, circuit breakers, logging, configuration, dataclasses, tests and profiling.

| Example | Notes |
| --- | --- |
| [`big_o_membership.py`](reliability/big_o_membership.py) | The big-O trap — `x in some_list` inside a loop is quadratic |
| [`circuit_breaker.py`](reliability/circuit_breaker.py) | Circuit breaker — stop hammering a dependency that is already down |
| [`config_from_env.py`](reliability/config_from_env.py) | Configuration from environment variables — parse once, validate, fail loudly |
| [`cprofile_call_counts.py`](reliability/cprofile_call_counts.py) | cProfile + pstats — find the hot spot by call counts, not by guessing |
| [`dataclass_pitfalls.py`](reliability/dataclass_pitfalls.py) | Dataclass pitfalls — shared defaults, default_factory, and what frozen means |
| [`doctest_docstrings.py`](reliability/doctest_docstrings.py) | doctest — make docstring examples prove themselves |
| [`idempotency_keys.py`](reliability/idempotency_keys.py) | Idempotency keys — retries are safe only if the server can recognise them |
| [`logging_dictconfig.py`](reliability/logging_dictconfig.py) | logging.config.dictConfig — and why every line shows up twice |
| [`randomized_tests.py`](reliability/randomized_tests.py) | Testing beyond the examples — the author's own examples are not a test suite |
| [`retry_backoff.py`](reliability/retry_backoff.py) | Retries with exponential backoff and jitter — and a clock you can inject |
| [`structured_json_logs.py`](reliability/structured_json_logs.py) | Structured JSON logs — one event per line, fields instead of f-strings |
| [`tracemalloc_deterministic.py`](reliability/tracemalloc_deterministic.py) | tracemalloc — where does the memory go, reported in a way that is stable |
| [`type_hints_runtime.py`](reliability/type_hints_runtime.py) | Type hints are not checked at runtime — validate where data enters |

## review

Small tools I use when reviewing: an AST-based code reviewer and a dependency name check.

| Example | Notes |
| --- | --- |
| [`code_reviewer.py`](review/code_reviewer.py) | Code reviewer v4 — a report with locations, severities and a CI gate |
| [`slopsquatting.py`](review/slopsquatting.py) | Slopsquatting v2 — check the declared dependencies, not only the imports |
