"""CWE-1287: int() and float() accept far more than ASCII digits

https://cwe.mitre.org/data/definitions/1287.html   (improper validation of specified type of input)

int(s) is often used as the validation step: "if it parses, it is a number".
But int() accepts any Unicode decimal digit ("١٢٣" and fullwidth "０９"),
underscores between digits ("1_000"), surrounding whitespace and newlines,
and a sign. A WAF or audit rule that looks for the ASCII spelling misses the
other ones, and two components that parse the same field differently will
disagree about which record it names. str.isdigit() is no better: it accepts
"²", which int() then rejects with an unhandled ValueError. float() adds
"nan", "inf" and "1e309"; NaN fails every comparison, so a check written as
"reject if x < 0 or x > limit" lets it through. Decimal is laxer still.

Decide the exact grammar, check it with re.fullmatch on an explicit ASCII
class, then convert, then range-check, and keep NaN/inf out with
math.isfinite when floats are involved.
"""

import math
import re
from decimal import Decimal, InvalidOperation

INPUTS = ["42", "\u0661\u0662\u0663", "\uff10\uff19", "1_000", " 42\n", "+5", "-1",
          "\xb2", "nan", "1e309", "\u0e51\u0e52", "1__0"]
QUANTITY = re.compile(r"[0-9]{1,4}")


def parse(fn, s: str) -> str:
    try:
        return repr(fn(s))
    except (ValueError, InvalidOperation) as exc:
        return type(exc).__name__


def noncompliant_amount(s: str) -> float:
    amount = float(s)
    if amount < 0 or amount > 1000:
        raise ValueError("out of range")
    return amount


def compliant_quantity(s: str) -> int:
    if not QUANTITY.fullmatch(s):
        raise ValueError("not 1-4 ASCII digits")
    value = int(s)
    if not 1 <= value <= 1000:
        raise ValueError("out of range")
    return value


def compliant_amount(s: str) -> float:
    if not re.fullmatch(r"[0-9]{1,4}(?:\.[0-9]{1,2})?", s):
        raise ValueError("bad format")
    amount = float(s)
    if not (math.isfinite(amount) and 0 <= amount <= 1000):
        raise ValueError("out of range")
    return amount


def main() -> None:
    cols = {"isdigit": str.isdigit, "int": int, "float": float, "Decimal": Decimal,
            "compliant": compliant_quantity}
    print(f"{'input':22}" + "".join(f"{c:>18}" for c in cols))
    for s in INPUTS:
        cells = []
        for name, fn in cols.items():
            cells.append(str(fn(s)) if name == "isdigit" else parse(fn, s))
        print(f"{ascii(s):22}" + "".join(f"{c:>18}" for c in cells))
    print()
    for s in ("250.5", "nan", "-inf", "1e309", "-0"):
        print(f"amount {s!r:8} noncompliant {parse(noncompliant_amount, s):12} "
              f"compliant {parse(compliant_amount, s)}")


if __name__ == "__main__":
    main()

# Output:
# input                            isdigit               int             float           Decimal         compliant
# '42'                                True                42              42.0     Decimal('42')                42
# '\u0661\u0662\u0663'                True               123             123.0    Decimal('123')        ValueError
# '\uff10\uff19'                      True                 9               9.0      Decimal('9')        ValueError
# '1_000'                            False              1000            1000.0   Decimal('1000')        ValueError
# ' 42\n'                            False                42              42.0     Decimal('42')        ValueError
# '+5'                               False                 5               5.0      Decimal('5')        ValueError
# '-1'                               False                -1              -1.0     Decimal('-1')        ValueError
# '\xb2'                              True        ValueError        ValueError  InvalidOperation        ValueError
# 'nan'                              False        ValueError               nan    Decimal('NaN')        ValueError
# '1e309'                            False        ValueError               inf Decimal('1E+309')        ValueError
# '\u0e51\u0e52'                      True                12              12.0     Decimal('12')        ValueError
# '1__0'                             False        ValueError        ValueError     Decimal('10')        ValueError
#
# amount '250.5'  noncompliant 250.5        compliant 250.5
# amount 'nan'    noncompliant nan          compliant ValueError
# amount '-inf'   noncompliant ValueError   compliant ValueError
# amount '1e309'  noncompliant ValueError   compliant ValueError
# amount '-0'     noncompliant -0.0         compliant ValueError
