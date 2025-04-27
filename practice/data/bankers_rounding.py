"""Banker's rounding — ``round(2.5)`` is 2, and ``round(2.675, 2)`` is 2.67

When a spec says "round to the nearest whole unit, halves up", the obvious
code is ``round(x)``. Python's ``round`` uses round-half-to-even (banker's rounding),
so 0.5 -> 0, 1.5 -> 2, 2.5 -> 2. On top of that, a float like 2.675 is really
2.67499999..., so even half-even rounding to two places goes "down". Format
specs (``f"{x:.0f}"``) follow the same rules.

Review note: if the business rule names a rounding mode, the code must name
it too. Use ``Decimal`` built from a string and ``quantize`` with
``ROUND_HALF_UP`` (or whatever the rule says). Half-even is a fine default for
statistics because it is unbiased; it is just not what most invoices expect.
"""

from decimal import ROUND_HALF_EVEN, ROUND_HALF_UP, Decimal


def round_noncompliant(value: float) -> int:
    return round(value)


def round_compliant(value: str, places: str = "1") -> Decimal:
    return Decimal(value).quantize(Decimal(places), rounding=ROUND_HALF_UP)


def main() -> None:
    halves = ["0.5", "1.5", "2.5", "3.5", "-2.5"]
    print("value   round()  f'{:.0f}'  HALF_UP  HALF_EVEN")
    for h in halves:
        f = float(h)
        half_even = Decimal(h).quantize(Decimal("1"), rounding=ROUND_HALF_EVEN)
        print(f"{h:>5}  {round_noncompliant(f):>7}  {f'{f:.0f}':>9}  "
              f"{round_compliant(h):>7}  {half_even:>9}")

    print()
    print("round(2.675, 2)       =", round(2.675, 2))
    print("2.675 is really        ", f"{2.675:.20f}")
    print("Decimal('2.675') HALF_UP =", round_compliant("2.675", "0.01"))

    # Rounding each line vs rounding the total gives different invoices.
    lines = ["0.125", "0.125", "0.125", "0.125"]
    per_line = sum(round_compliant(x, "0.01") for x in lines)
    on_total = round_compliant(str(sum(Decimal(x) for x in lines)), "0.01")
    print("round per line then sum =", per_line, " round the sum =", on_total)


if __name__ == "__main__":
    main()

# Output:
# value   round()  f'{:.0f}'  HALF_UP  HALF_EVEN
#   0.5        0          0        1          0
#   1.5        2          2        2          2
#   2.5        2          2        3          2
#   3.5        4          4        4          4
#  -2.5       -2         -2       -3         -2
#
# round(2.675, 2)       = 2.67
# 2.675 is really         2.67499999999999982236
# Decimal('2.675') HALF_UP = 2.68
# round per line then sum = 0.52  round the sum = 0.50
