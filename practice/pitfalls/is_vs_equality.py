"""``is`` vs ``==`` — identity only looks like equality for small ints and interned strings

It is easy to write ``if status is "active"`` or
``if count is 0``. In a quick REPL test it works, because CPython caches the
small integers and interns many short string literals, so two "equal" values
happen to be the same object. The cached range is an implementation detail:
it was -5..256 for years and CPython 3.15 widened it to 1024, so an ``is``
check can even change behaviour across an interpreter upgrade. With values
built at runtime (parsed from JSON, read from a socket, computed) the objects
differ and ``is`` returns False.

Review note: ``is`` is for singletons (``None``, ``True``, ``False``,
``Ellipsis``, sentinel objects) and deliberate identity checks. Everything else
uses ``==``. CPython even emits a ``SyntaxWarning`` for ``is`` with a literal;
treat it as an error in CI with ``-W error::SyntaxWarning``.
"""

import sys
import warnings


def is_active_noncompliant(status: str) -> bool:
    return status is sys.intern("active")  # stands in for: status is "active"


def is_active_compliant(status: str) -> bool:
    return status == "active"


def main() -> None:
    # Values built at runtime, as they would be after parsing a request.
    small_a, small_b = int("100"), int("100")
    big_a, big_b = int("50000"), int("50000")
    print(f"int   100: == {small_a == small_b}, is {small_a is small_b}   (small-int cache)")
    print(f"int 50000: == {big_a == big_b}, is {big_a is big_b}  (separate objects)")

    status = "".join(["act", "ive"])  # e.g. json.loads(body)["status"]
    print("noncompliant: status is 'active' ->", is_active_noncompliant(status))
    print("compliant:    status == 'active' ->", is_active_compliant(status))

    # sys.intern makes identity work for strings, which is exactly why it is
    # misleading: correctness now depends on who interned what.
    print("after sys.intern(status):", is_active_noncompliant(sys.intern(status)))

    # The compiler warns when it sees `is` with a literal.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        compile("count = 0\nif count is 0: pass\n", "<snippet>", "exec")
    for w in caught:
        print(f"{w.category.__name__}: {w.message}")

    # The legitimate use: singletons.
    value = None
    print("value is None ->", value is None)


if __name__ == "__main__":
    main()

# Output:
# int   100: == True, is True   (small-int cache)
# int 50000: == True, is False  (separate objects)
# noncompliant: status is 'active' -> False
# compliant:    status == 'active' -> True
# after sys.intern(status): True
# SyntaxWarning: "is" with 'int' literal. Did you mean "=="?
# value is None -> True
