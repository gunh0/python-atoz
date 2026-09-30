"""CWE-400: huge integers — keep sys.set_int_max_str_digits and add your own bound

https://cwe.mitre.org/data/definitions/400.html   (CVE-2020-10735)

Converting a decimal string to int (and back) used to be quadratic, so one
JSON field of a few hundred thousand digits pinned a CPU. Since 3.11 the
interpreter refuses conversions of more than 4300 digits with ValueError,
in int(), str(), json and f-strings alike. That limit is a safety net, not
input validation: setting it to 0 because "big numbers raise errors" turns
the old DoS back on, and it does not cover the paths that never go through a
decimal string. Power-of-two bases are exempt (int(s, 16)), and
int(Decimal("1e100000")) builds a 100 001-digit number from 11 bytes of
input; the error only appears later, when something tries to print it.

Validate the textual form against the range your domain needs before
converting (an account id has at most 18 digits, not 4300), and give json
a parse_int / parse_float that enforces it.
"""

import json
import re
import sys
from decimal import Decimal

ID = re.compile(r"[0-9]{1,18}")


def bounded_int(s: str) -> int:
    if not ID.fullmatch(s):
        raise ValueError(f"integer of {len(s)} chars not allowed")
    return int(s)


def no_floats(s: str):
    raise ValueError(f"number {s[:10]}... not allowed" if len(s) > 10 else f"number {s} not allowed")


def compliant_loads(body: str):
    return json.loads(body, parse_int=bounded_int, parse_float=no_floats, parse_constant=no_floats)


def attempt(fn) -> str:
    try:
        r = fn()
    except ValueError as exc:
        return "ValueError: " + str(exc).split(";")[0].split(": value has")[0]
    if isinstance(r, int):
        return f"int with {r.bit_length():,} bits"
    return f"{type(r).__name__} {r!r}"[:60]


def main() -> None:
    print(f"default limit: {sys.int_info.default_max_str_digits} digits, "
          f"current: {sys.get_int_max_str_digits()}")
    big = "9" * 5000
    print("int('9' * 4300)             ", attempt(lambda: int("9" * 4300)))
    print("int('9' * 5000)             ", attempt(lambda: int(big)))
    print("json.loads('[9...9]')       ", attempt(lambda: json.loads(f"[{big}]")))
    print("str(10 ** 5000)             ", attempt(lambda: str(10 ** 5000)))
    print()
    print("paths the limit does not cover:")
    print("  int('f' * 10000, 16)      ", attempt(lambda: int("f" * 10000, 16)))
    huge = int(Decimal("1e100000"))
    print("  int(Decimal('1e100000'))  ", attempt(lambda: huge))
    print("  ...then logging it        ", attempt(lambda: f"amount={huge}"))
    print()
    print("noncompliant: sys.set_int_max_str_digits(0) 'fixes' the errors:")
    sys.set_int_max_str_digits(0)
    print("  json.loads('[9 * 50000]') ", attempt(lambda: json.loads(f"[{'9' * 50_000}]")[0]))
    sys.set_int_max_str_digits(sys.int_info.default_max_str_digits)
    print()
    for body in ('{"account": 1234567890}', f'{{"account": {big}}}',
                 '{"account": 1e100000}', '{"account": NaN}'):
        label = body if len(body) < 30 else body[:24] + "...}"
        print(f"compliant {label:28} ", attempt(lambda: compliant_loads(body)))


if __name__ == "__main__":
    main()

# Output:
# default limit: 4300 digits, current: 4300
# int('9' * 4300)              int with 14,285 bits
# int('9' * 5000)              ValueError: Exceeds the limit (4300 digits) for integer string conversion
# json.loads('[9...9]')        ValueError: Exceeds the limit (4300 digits) for integer string conversion
# str(10 ** 5000)              ValueError: Exceeds the limit (4300 digits) for integer string conversion
#
# paths the limit does not cover:
#   int('f' * 10000, 16)       int with 40,000 bits
#   int(Decimal('1e100000'))   int with 332,193 bits
#   ...then logging it         ValueError: Exceeds the limit (4300 digits) for integer string conversion
#
# noncompliant: sys.set_int_max_str_digits(0) 'fixes' the errors:
#   json.loads('[9 * 50000]')  int with 166,097 bits
#
# compliant {"account": 1234567890}       dict {'account': 1234567890}
# compliant {"account": 999999999999...}  ValueError: integer of 5000 chars not allowed
# compliant {"account": 1e100000}         ValueError: number 1e100000 not allowed
# compliant {"account": NaN}              ValueError: number NaN not allowed
