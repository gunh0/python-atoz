"""Floor division and modulo with negatives — Python floors, C/Java/JS truncate

Code ported from Java, C or JavaScript keeps its arithmetic idioms, and so
does code written "from memory" of those languages. Python's ``//``
rounds toward negative infinity and ``%`` takes the sign of the divisor, so
``-7 // 2 == -4`` and ``-7 % 2 == 1``. ``int(a / b)`` truncates instead, but goes
through a float and silently loses precision for large integers.

Review note: ask which rounding the domain needs. For "how many full
buckets", negative offsets, or clock arithmetic, Python's floor semantics are
usually what you want. For a port that must match another system, use
``math.trunc``-style integer logic explicitly, never ``int(a / b)`` on big ints.
"""

import math


def bucket_noncompliant(offset_seconds: int, size: int = 3600) -> int:
    # Ported from JS: Math.trunc(offset / size)
    return int(offset_seconds / size)


def bucket_compliant(offset_seconds: int, size: int = 3600) -> int:
    return offset_seconds // size


def trunc_div(a: int, b: int) -> int:
    """Integer division rounding toward zero, without going through float."""
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q


def main() -> None:
    print(" a   b   a//b  a%b  int(a/b)  math.fmod  trunc_div")
    for a, b in [(7, 2), (-7, 2), (7, -2), (-7, -2)]:
        print(f"{a:>2}  {b:>2}  {a // b:>5}  {a % b:>3}  {int(a / b):>8}  "
              f"{math.fmod(a, b):>9}  {trunc_div(a, b):>9}")

    # Hour buckets for events before and after an epoch: -1s is hour -1.
    for offset in (-1, 0, 3599, 3600):
        print(f"offset {offset:>5}s  noncompliant bucket {bucket_noncompliant(offset):>2}"
              f"  compliant bucket {bucket_compliant(offset):>2}")

    # Wrap a weekday index backwards: Python's % already gives 0..6.
    print("(0 - 1) % 7 =", (0 - 1) % 7, "  math.fmod(0 - 1, 7) =", math.fmod(0 - 1, 7))

    # int(a / b) goes through float and loses digits.
    big = 10**20 + 1
    print("int(big / 1) == big:", int(big / 1) == big, " big // 1 == big:", big // 1 == big)
    print("divmod(-7, 2) =", divmod(-7, 2))


if __name__ == "__main__":
    main()

# Output:
#  a   b   a//b  a%b  int(a/b)  math.fmod  trunc_div
#  7   2      3    1         3        1.0          3
# -7   2     -4    1        -3       -1.0         -3
#  7  -2     -4   -1        -3        1.0         -3
# -7  -2      3   -1         3       -1.0          3
# offset    -1s  noncompliant bucket  0  compliant bucket -1
# offset     0s  noncompliant bucket  0  compliant bucket  0
# offset  3599s  noncompliant bucket  0  compliant bucket  0
# offset  3600s  noncompliant bucket  1  compliant bucket  1
# (0 - 1) % 7 = 6   math.fmod(0 - 1, 7) = -1.0
# int(big / 1) == big: False  big // 1 == big: True
# divmod(-7, 2) = (-4, 1)
