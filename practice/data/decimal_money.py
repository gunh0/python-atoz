"""Decimal for money — and why ``Decimal(0.1)`` is not ``Decimal("0.1")``

Code that follows "use Decimal for money" often converts at the last moment:
``Decimal(price)`` where ``price`` is already a float from ``json.loads`` or a
CSV parser. ``Decimal`` faithfully converts the float's exact binary value, so
the representation error is now preserved in 50+ digits. Mixing ``Decimal`` and
``float`` in arithmetic raises ``TypeError``, which tempts a quick ``float()``
cast that throws the precision away again.

Review note: money must be ``Decimal`` from the moment it is parsed
(``Decimal(str)``, ``json.loads(..., parse_float=Decimal)``) or integer minor
units. Quantize to the currency's exponent at defined points, and consider a
local context with ``FloatOperation`` trapped so accidental floats fail loudly.
"""

import decimal
import json
from decimal import ROUND_HALF_UP, Decimal

CENT = Decimal("0.01")
BODY = '{"items": [{"sku": "A1", "price": 0.10}, {"sku": "B2", "price": 0.20}], "paid": 0.30}'


def balance_noncompliant(body: str) -> Decimal:
    data = json.loads(body)  # floats already
    total = sum(Decimal(i["price"]) for i in data["items"])
    return Decimal(data["paid"]) - total


def balance_compliant(body: str) -> Decimal:
    data = json.loads(body, parse_float=Decimal)
    total = sum((i["price"] for i in data["items"]), Decimal("0"))
    return (data["paid"] - total).quantize(CENT, rounding=ROUND_HALF_UP)


def main() -> None:
    print("Decimal(0.1)   =", Decimal(0.1))
    print("Decimal('0.1') =", Decimal("0.1"))
    print("Decimal(str(0.1)) =", Decimal(str(0.1)), "(works, but the float was still parsed first)")

    print("noncompliant: balance =", balance_noncompliant(BODY))
    print("compliant:    balance =", balance_compliant(BODY))

    try:
        Decimal("1.10") + 0.2
    except TypeError as exc:
        # The message names the type differently in the C and pure-Python decimal modules.
        print("Decimal + float ->", type(exc).__name__, "(no implicit mixing)")

    # Trap silent float -> Decimal conversions in money code paths.
    with decimal.localcontext() as ctx:
        ctx.traps[decimal.FloatOperation] = True
        try:
            Decimal(19.99)
        except decimal.FloatOperation:
            print("FloatOperation trapped: Decimal(19.99) rejected inside money context")
        print("Decimal('19.99') still fine:", Decimal("19.99"))

    # Splitting a bill: quantize, then put the remainder somewhere explicit.
    total, people = Decimal("100.00"), 3
    share = (total / people).quantize(CENT, rounding=decimal.ROUND_DOWN)
    shares = [share] * people
    shares[0] += total - sum(shares)
    print("split 100.00 three ways:", [str(s) for s in shares], "sum =", sum(shares))


if __name__ == "__main__":
    main()

# Output:
# Decimal(0.1)   = 0.1000000000000000055511151231257827021181583404541015625
# Decimal('0.1') = 0.1
# Decimal(str(0.1)) = 0.1 (works, but the float was still parsed first)
# noncompliant: balance = -2.775557561565156540423631668E-17
# compliant:    balance = 0.00
# Decimal + float -> TypeError (no implicit mixing)
# FloatOperation trapped: Decimal(19.99) rejected inside money context
# Decimal('19.99') still fine: 19.99
# split 100.00 three ways: ['33.34', '33.33', '33.33'] sum = 100.00
