"""Sort stability and keys — strings sort as text, ties keep input order

It is easy to sort whatever you are handed: ``sorted(versions)``, ``sorted(names)``,
``rows.sort(key=lambda r: r["dept"])``. Strings compare code point by code
point, so "1.10.0" sorts before "1.9.2" and "Zoe" before "alice". ``None`` in
the data raises ``TypeError`` halfway through a report. And multi-key sorts
with a mix of ascending and descending text keys cannot be expressed by
negating a string.

Review note: make the key express the meaning (parse versions into tuples
of ints, ``str.casefold`` for names, ``(x is None, x)`` to put missing values
last). Python's sort is stable, also with ``reverse=True``, so a multi-key sort
can be done as successive sorts from the least to the most significant key.
"""

VERSIONS = ["1.10.0", "1.9.2", "1.2.0", "1.10.1"]
NAMES = ["bob", "Alice", "alice", "Bob", "Zoe"]
ROWS = [
    {"dept": "ops", "name": "kim", "level": 2},
    {"dept": "dev", "name": "lee", "level": 3},
    {"dept": "ops", "name": "park", "level": 3},
    {"dept": "dev", "name": "choi", "level": 3},
    {"dept": "dev", "name": "jung", "level": 1},
]


def version_key(v: str) -> tuple[int, ...]:
    return tuple(int(part) for part in v.split("."))


def main() -> None:
    print("noncompliant versions:", sorted(VERSIONS))
    print("compliant versions:   ", sorted(VERSIONS, key=version_key))
    print("latest (max, text):   ", max(VERSIONS), " latest (max, key):", max(VERSIONS, key=version_key))

    print("noncompliant names:", sorted(NAMES))
    print("compliant names:   ", sorted(NAMES, key=str.casefold), "(ties keep input order)")

    # dept ascending, then name descending: two stable passes, least significant first.
    by_name_desc = sorted(ROWS, key=lambda r: r["name"], reverse=True)
    by_dept = sorted(by_name_desc, key=lambda r: r["dept"])
    print("dept asc, name desc:", [f"{r['dept']}/{r['name']}" for r in by_dept])

    # reverse=True is still stable: equal levels keep their original order.
    by_level = sorted(ROWS, key=lambda r: r["level"], reverse=True)
    print("level desc (stable):", [f"{r['level']}/{r['name']}" for r in by_level])

    scores = [70, None, 85, None, 60]
    try:
        sorted(scores)
    except TypeError as exc:
        print("sorted with None ->", type(exc).__name__ + ":", exc)
    print("None last:          ", sorted(scores, key=lambda s: (s is None, s or 0)))


if __name__ == "__main__":
    main()

# Output:
# noncompliant versions: ['1.10.0', '1.10.1', '1.2.0', '1.9.2']
# compliant versions:    ['1.2.0', '1.9.2', '1.10.0', '1.10.1']
# latest (max, text):    1.9.2  latest (max, key): 1.10.1
# noncompliant names: ['Alice', 'Bob', 'Zoe', 'alice', 'bob']
# compliant names:    ['Alice', 'alice', 'bob', 'Bob', 'Zoe'] (ties keep input order)
# dept asc, name desc: ['dev/lee', 'dev/jung', 'dev/choi', 'ops/park', 'ops/kim']
# level desc (stable): ['3/lee', '3/park', '3/choi', '2/kim', '1/jung']
# sorted with None -> TypeError: '<' not supported between instances of 'NoneType' and 'int'
# None last:           [60, 70, 85, None, None]
