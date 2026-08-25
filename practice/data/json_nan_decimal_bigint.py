"""json with NaN, Decimal and big ints — valid for Python, broken for everyone else

``json.dumps`` looks like a safe default, it is usually paired with a
quick ``default=float`` when ``Decimal`` raises ``TypeError``. Three things go wrong at
the boundary to other systems. Python writes ``NaN``/``Infinity`` by default,
which is not JSON, so a strict parser (a browser's ``JSON.parse``, Go, jq)
rejects the whole document. ``default=float`` rounds money and long decimals.
Integers above 2**53 are fine in Python but lose precision in JavaScript and
other double-based parsers, which turns IDs into different IDs.

Review note: dump with ``allow_nan=False`` and decide what a missing
measurement is (``null``). Serialize ``Decimal`` and 64-bit IDs as strings
when the consumer is not Python. On input, ``parse_constant`` can reject
``NaN``, ``parse_float=Decimal`` keeps amounts exact, and the int digit limit
(``sys.get_int_max_str_digits``) stops a huge-number DoS.
"""

import json
import math
from decimal import Decimal

READING = {"sensor": "t1", "value": float("nan")}
INVOICE = {"total": Decimal("12345678901234567.89")}
EVENT = {"id": 2**53 + 1}


def reject_constant(name: str):
    raise ValueError(f"non-standard JSON constant {name}")


def to_json_value(obj):
    if isinstance(obj, Decimal):
        return str(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def main() -> None:
    print("noncompliant NaN:     ", json.dumps(READING))
    try:
        json.dumps(READING, allow_nan=False)
    except ValueError as exc:
        print("allow_nan=False ->     ValueError:", str(exc).split(":")[0])
    clean = {k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in READING.items()}
    print("compliant NaN:        ", json.dumps(clean, allow_nan=False))

    try:
        json.dumps(INVOICE)
    except TypeError as exc:
        print("Decimal ->             TypeError:", exc)
    print("noncompliant Decimal: ", json.dumps(INVOICE, default=float))
    print("compliant Decimal:    ", json.dumps(INVOICE, default=to_json_value))

    as_js_number = float(EVENT["id"])          # what a double-based parser keeps
    print("big int in Python:    ", json.dumps(EVENT), " as JS reads it:", int(as_js_number),
          " same id?", int(as_js_number) == EVENT["id"])
    print("compliant big int:    ", json.dumps({"id": str(EVENT["id"])}))

    print("loads accepts NaN:    ", json.loads('{"v": NaN}'))
    try:
        json.loads('{"v": NaN}', parse_constant=reject_constant)
    except ValueError as exc:
        print("parse_constant ->      ValueError:", exc)
    print("parse_float=Decimal:  ", json.loads('{"total": 0.10}', parse_float=Decimal))

    try:
        json.loads("1" * 5000)
    except ValueError:
        print("5000-digit int ->      ValueError (int max str digits limit)")

    print("int keys become str:  ", json.loads(json.dumps({1: "a", 2: "b"})))


if __name__ == "__main__":
    main()

# Output:
# noncompliant NaN:      {"sensor": "t1", "value": NaN}
# allow_nan=False ->     ValueError: Out of range float values are not JSON compliant
# compliant NaN:         {"sensor": "t1", "value": null}
# Decimal ->             TypeError: Object of type Decimal is not JSON serializable
# noncompliant Decimal:  {"total": 1.2345678901234568e+16}
# compliant Decimal:     {"total": "12345678901234567.89"}
# big int in Python:     {"id": 9007199254740993}  as JS reads it: 9007199254740992  same id? False
# compliant big int:     {"id": "9007199254740993"}
# loads accepts NaN:     {'v': nan}
# parse_constant ->      ValueError: non-standard JSON constant NaN
# parse_float=Decimal:   {'total': Decimal('0.10')}
# 5000-digit int ->      ValueError (int max str digits limit)
# int keys become str:   {'1': 'a', '2': 'b'}
