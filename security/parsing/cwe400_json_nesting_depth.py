"""CWE-400: uncontrolled resource consumption — bound JSON before you parse it

https://cwe.mitre.org/data/definitions/400.html   (CWE-674: uncontrolled recursion)

json.loads() has no depth or size option. A 200 KB body of "[[[[...]]]]"
either makes the parser itself raise RecursionError (3.13) or parses fine
and hands your code a 100 000-level structure (3.14+, where the C stack
check replaced the old recursion counter), and the first recursive function
that walks it, yours, a logger or a serializer, raises instead. Either way
the request dies with an unhandled exception, and how deep is "too deep"
depends on the version and the thread's stack size.

Enforce your own limits first: a body size cap and a linear pre-scan of the
nesting depth (brackets inside strings do not count). While you are at it,
make the loader strict: json accepts NaN/Infinity by default, and on
duplicate keys the last one silently wins, so {"role":"user","role":"admin"}
means different things to different parsers in your stack.
"""

import json

MAX_BYTES = 64 * 1024
MAX_DEPTH = 32


def leaves(obj) -> int:
    """Typical recursive consumer: count scalar values."""
    if isinstance(obj, list):
        return sum(leaves(v) for v in obj)
    if isinstance(obj, dict):
        return sum(leaves(v) for v in obj.values())
    return 1


def noncompliant(body: str) -> str:
    return f"{leaves(json.loads(body))} leaves"


def nesting_depth(text: str) -> int:
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def reject_constant(name: str):
    raise ValueError(f"{name} is not allowed")


def no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError(f"duplicate key in {keys}")
    return dict(pairs)


def compliant(body: str) -> str:
    if len(body.encode()) > MAX_BYTES:
        raise ValueError(f"body over {MAX_BYTES} bytes")
    if (depth := nesting_depth(body)) > MAX_DEPTH:
        raise ValueError(f"nesting depth {depth} over {MAX_DEPTH}")
    data = json.loads(body, parse_constant=reject_constant, object_pairs_hook=no_duplicates)
    return f"{leaves(data)} leaves"


def attempt(fn, body: str) -> str:
    try:
        return fn(body)
    except RecursionError:
        return "RecursionError (unhandled -> HTTP 500)"
    except ValueError as exc:
        return f"rejected: {exc}"


def main() -> None:
    bodies = {
        "normal": '{"items": [1, 2, [3, 4]], "note": "[[[ in a string ]]]"}',
        "depth 40": "[" * 40 + "]" * 40,
        "depth 20000 (40 KB)": "[" * 20_000 + "]" * 20_000,
        "depth 100000": "[" * 100_000 + "]" * 100_000,
        "1 MB array": "[" + ",".join(["1"] * 500_000) + "]",
        "NaN": '{"amount": NaN}',
        "duplicate key": '{"role": "user", "role": "admin"}',
    }
    for label, body in bodies.items():
        print(f"{label}:")
        print(f"  noncompliant {attempt(noncompliant, body)}")
        print(f"  compliant    {attempt(compliant, body)}")
    print()
    print("what noncompliant made of the duplicate key:", json.loads(bodies["duplicate key"]))


if __name__ == "__main__":
    main()

# Output:
# normal:
#   noncompliant 5 leaves
#   compliant    5 leaves
# depth 40:
#   noncompliant 0 leaves
#   compliant    rejected: nesting depth 40 over 32
# depth 20000 (40 KB):
#   noncompliant RecursionError (unhandled -> HTTP 500)
#   compliant    rejected: nesting depth 20000 over 32
# depth 100000:
#   noncompliant RecursionError (unhandled -> HTTP 500)
#   compliant    rejected: body over 65536 bytes
# 1 MB array:
#   noncompliant 500000 leaves
#   compliant    rejected: body over 65536 bytes
# NaN:
#   noncompliant 1 leaves
#   compliant    rejected: NaN is not allowed
# duplicate key:
#   noncompliant 1 leaves
#   compliant    rejected: duplicate key in ['role', 'role']
#
# what noncompliant made of the duplicate key: {'role': 'admin'}
