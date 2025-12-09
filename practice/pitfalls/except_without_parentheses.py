# requires-python: >=3.14
"""``except A, B:`` without parentheses (PEP 758) — and the Python 2 ghost it revives

https://peps.python.org/pep-0758/

Since 3.14, ``except ValueError, TypeError:`` is legal and catches both, same
as the parenthesized tuple. That is convenient, and it also reopens an old
trap. Python 2 habits linger, and there ``except ValueError, err:``
meant "bind the exception to ``err``". From Python 3.0 to 3.13 that line was a
``SyntaxError`` and failed immediately. On 3.14 it compiles, the happy path
works, and only the error path evaluates the tuple ``(ValueError, err)``:
``NameError`` if ``err`` is unbound, ``TypeError`` if it is some other object.

Review note: binding still requires ``except (A, B) as err:``; an
unparenthesized list followed by a lowercase name is almost certainly the
Python 2 form. If the project supports 3.13, the new syntax is a
``SyntaxError`` there; ``ast.parse(src, feature_version=(3, 13))`` in CI
catches it before release.
"""

import ast


def parse_port_noncompliant(text: str) -> int:
    try:
        return int(text)
    except ValueError, err:            # Python 2 habit: means (ValueError, err) now
        return -1


def parse_port_pep758(text) -> int:
    try:
        return int(text)
    except ValueError, TypeError:      # 3.14+: catches both, no binding
        return -1


def parse_port_compliant(text) -> int:
    try:
        return int(text)
    except (ValueError, TypeError) as err:
        print(f"  compliant: rejected {text!r} ({type(err).__name__})")
        return -1


def main() -> None:
    print("noncompliant parse('8080')  ->", parse_port_noncompliant("8080"))
    try:
        parse_port_noncompliant("http")
    except NameError as exc:
        print("noncompliant parse('http')  -> NameError:", exc)
        print("  original error kept as __context__:", type(exc.__context__).__name__)

    print("PEP 758 parse('http'), parse(None) ->", parse_port_pep758("http"), parse_port_pep758(None))
    print("compliant:", parse_port_compliant("http"), parse_port_compliant(None))

    with_as = "try:\n    pass\nexcept ValueError, TypeError as err:\n    pass\n"
    try:
        compile(with_as, "<snippet>", "exec")
    except SyntaxError as exc:
        print("unparenthesized + as -> SyntaxError:", exc.msg)

    snippet = "try:\n    pass\nexcept ValueError, TypeError:\n    pass\n"
    handler = ast.parse(snippet).body[0].handlers[0]
    print("parsed handler type:", type(handler.type).__name__,
          [n.id for n in handler.type.elts])
    for version in ((3, 13), (3, 14)):
        try:
            ast.parse(snippet, feature_version=version)
            print(f"feature_version={version}: ok")
        except SyntaxError as exc:
            print(f"feature_version={version}: SyntaxError: {exc.msg}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant parse('8080')  -> 8080
# noncompliant parse('http')  -> NameError: name 'err' is not defined
#   original error kept as __context__: ValueError
# PEP 758 parse('http'), parse(None) -> -1 -1
#   compliant: rejected 'http' (ValueError)
#   compliant: rejected None (TypeError)
# compliant: -1 -1
# unparenthesized + as -> SyntaxError: multiple exception types must be parenthesized when using 'as'
# parsed handler type: Tuple ['ValueError', 'TypeError']
# feature_version=(3, 13): SyntaxError: except expressions without parentheses are only supported in Python 3.14 and greater
# feature_version=(3, 14): ok
