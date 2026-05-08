"""``return`` in ``finally`` — the exception just disappears

Code that "always returns a status" sometimes puts the ``return`` in the
``finally`` block: ``try: write(); finally: return {"ok": ...}``. A ``return``,
``break`` or ``continue`` inside ``finally`` discards any in-flight exception
and overrides an earlier ``return`` in ``try``. The disk-full error, the
``KeyboardInterrupt``, the failed assertion: all silently replaced by a normal
return value. Python 3.14 (PEP 765) now emits a ``SyntaxWarning`` when it
compiles such code, but 3.13 says nothing and warnings are easy to miss.

Review note: ``finally`` is for cleanup only. Compute the result in ``try``
or ``except`` and return after the block. Turn ``SyntaxWarning`` into an error
in CI. The noncompliant functions below are compiled from source with that
warning suppressed so the example prints the same on 3.13, 3.14 and 3.15.
"""

import warnings

NONCOMPLIANT_SRC = '''
def save_noncompliant(data):
    try:
        if not data:
            raise OSError(28, "No space left on device")
        return "written"
    finally:
        return "ok"


def drain_noncompliant(items):
    done = []
    for item in items:
        try:
            if item == "bad":
                raise ValueError("bad record")
            done.append(item)
        finally:
            continue
    return done
'''

with warnings.catch_warnings():
    warnings.simplefilter("ignore", SyntaxWarning)   # 3.14+: PEP 765 warning
    exec(compile(NONCOMPLIANT_SRC, "<snippet>", "exec"))


def save_compliant(data) -> str:
    try:
        if not data:
            raise OSError(28, "No space left on device")
        result = "written"
    finally:
        pass  # close files, release locks: cleanup only
    return result


def main() -> None:
    print("noncompliant save(b'x'):", save_noncompliant(b"x"))      # noqa: F821
    print("noncompliant save(b''): ", save_noncompliant(b""), "(OSError swallowed)")  # noqa: F821
    print("noncompliant drain:     ", drain_noncompliant(["a", "bad", "c"]))  # noqa: F821

    print("compliant save(b'x'):   ", save_compliant(b"x"))
    try:
        save_compliant(b"")
    except OSError as exc:
        print("compliant save(b''):    ", f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant save(b'x'): ok
# noncompliant save(b''):  ok (OSError swallowed)
# noncompliant drain:      ['a', 'c']
# compliant save(b'x'):    written
# compliant save(b''):     OSError: [Errno 28] No space left on device
