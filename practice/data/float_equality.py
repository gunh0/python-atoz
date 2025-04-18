"""Float equality — ``0.1 + 0.2 == 0.3`` is False, and summing order matters

A reconciliation check ("do the line items add up to the invoice total?")
is usually written as a running ``total += x`` loop and then
``if total == invoice``. The numbers in the spec are decimal fractions, so
it looks exact. Binary floating point
cannot represent 0.1, 0.2 or 0.3 exactly, so the comparison fails for values
that are equal on paper, and passes or fails depending on summation order.

Review note: never compare computed floats with ``==``. Use
``math.isclose`` with an explicit tolerance that matches the domain (an
absolute tolerance near zero, since a relative one is useless there), use
``math.fsum`` for long sums, and for money use ``Decimal`` or integer cents
(see decimal_money.py). Since 3.12 the builtin ``sum()`` of floats is
compensated, so it hides the error that the hand-written loop still shows.
"""

import math


def totals_match_noncompliant(items: list[float], total: float) -> bool:
    running = 0.0
    for x in items:
        running += x
    return running == total


def totals_match_compliant(items: list[float], total: float) -> bool:
    return math.isclose(math.fsum(items), total, rel_tol=1e-9, abs_tol=1e-9)


def main() -> None:
    print("0.1 + 0.2       =", 0.1 + 0.2)
    print("0.1 + 0.2 == 0.3:", 0.1 + 0.2 == 0.3)
    print("repr of 0.1 to 20 places:", f"{0.1:.20f}")

    items = [0.1] * 10
    running = 0.0
    for x in items:
        running += x
    print("ten times += 0.1 =", running)
    print("noncompliant: running total == 1.0 ->", totals_match_noncompliant(items, 1.0))
    print("compliant:    fsum + isclose       ->", totals_match_compliant(items, 1.0))

    # Order of addition changes the result.
    print("(1e16 + 1.0) - 1e16 =", (1e16 + 1.0) - 1e16)
    print("(1e16 - 1e16) + 1.0 =", (1e16 - 1e16) + 1.0)
    print("fsum([1e16, 1.0, -1e16]) =", math.fsum([1e16, 1.0, -1e16]))

    # rel_tol alone never matches against zero.
    residue = 0.1 + 0.2 - 0.3
    print("residue          =", residue)
    print("isclose(residue, 0.0)               ->", math.isclose(residue, 0.0))
    print("isclose(residue, 0.0, abs_tol=1e-12) ->", math.isclose(residue, 0.0, abs_tol=1e-12))

    # NaN is not equal to itself, so `x == x` style checks also lie.
    nan = float("nan")
    print("nan == nan:", nan == nan, " math.isnan(nan):", math.isnan(nan))


if __name__ == "__main__":
    main()

# Output:
# 0.1 + 0.2       = 0.30000000000000004
# 0.1 + 0.2 == 0.3: False
# repr of 0.1 to 20 places: 0.10000000000000000555
# ten times += 0.1 = 0.9999999999999999
# noncompliant: running total == 1.0 -> False
# compliant:    fsum + isclose       -> True
# (1e16 + 1.0) - 1e16 = 0.0
# (1e16 - 1e16) + 1.0 = 1.0
# fsum([1e16, 1.0, -1e16]) = 1.0
# residue          = 5.551115123125783e-17
# isclose(residue, 0.0)               -> False
# isclose(residue, 0.0, abs_tol=1e-12) -> True
# nan == nan: False  math.isnan(nan): True
