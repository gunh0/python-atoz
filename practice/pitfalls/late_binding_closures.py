"""Late-binding closures — lambdas in a loop all see the last value

A common way to build "a dict of handlers, one per log level" is
``{lvl: lambda msg: f"[{lvl}] {msg}" for lvl in levels}``. It looks like each
lambda captures its own ``lvl``. It does not: a closure captures the *variable*,
not its value, and looks it up when the function is called. By then the loop
has finished and every handler sees the final level.

Review note: a ``lambda`` or nested ``def`` created inside a loop or
comprehension that refers to the loop variable is suspicious. Bind the value
at creation time with a default argument (``lvl=lvl``) or ``functools.partial``.
The same bug appears with callbacks registered in a loop (buttons, signal
handlers, thread targets).
"""

import functools


LEVELS = ["DEBUG", "INFO", "ERROR"]


def handlers_noncompliant():
    return {lvl: (lambda msg: f"[{lvl}] {msg}") for lvl in LEVELS}


def handlers_compliant_default():
    return {lvl: (lambda msg, lvl=lvl: f"[{lvl}] {msg}") for lvl in LEVELS}


def _format(lvl: str, msg: str) -> str:
    return f"[{lvl}] {msg}"


def handlers_compliant_partial():
    return {lvl: functools.partial(_format, lvl) for lvl in LEVELS}


def retry_delays_noncompliant() -> list[int]:
    # The same bug with plain closures appended in a for loop.
    funcs = []
    for attempt in range(1, 4):
        def delay():
            return 2 ** attempt
        funcs.append(delay)
    return [f() for f in funcs]


def main() -> None:
    for name, factory in [
        ("noncompliant", handlers_noncompliant),
        ("default arg ", handlers_compliant_default),
        ("partial     ", handlers_compliant_partial),
    ]:
        h = factory()
        print(f"{name}: {h['DEBUG']('cache miss')}  {h['INFO']('started')}")

    print("noncompliant: retry delays =", retry_delays_noncompliant())
    fixed = [lambda attempt=attempt: 2 ** attempt for attempt in range(1, 4)]
    print("compliant:    retry delays =", [f() for f in fixed])

    # What the closure really holds: a cell pointing at the loop variable.
    h = handlers_noncompliant()
    cell = h["DEBUG"].__closure__[0]
    print("closure cell for DEBUG handler contains:", cell.cell_contents)


if __name__ == "__main__":
    main()

# Output:
# noncompliant: [ERROR] cache miss  [ERROR] started
# default arg : [DEBUG] cache miss  [INFO] started
# partial     : [DEBUG] cache miss  [INFO] started
# noncompliant: retry delays = [8, 8, 8]
# compliant:    retry delays = [2, 4, 8]
# closure cell for DEBUG handler contains: ERROR
