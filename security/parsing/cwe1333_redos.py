r"""CWE-1333: ReDoS — nested quantifiers backtrack exponentially

https://cwe.mitre.org/data/definitions/1333.html

r"^(\w+\s?)*$" looks like a harmless "words separated by spaces" validator.
On "aaaa…a!" it fails, but only after trying every way to split the run of
a's between the inner \w+ and the outer *: 2**n attempts for n letters. Each
extra character doubles the work, so 40 characters in a form field pin a
worker for hours. Python's re is a backtracking engine with no step limit.

Remove the ambiguity. Since Python 3.11, re supports atomic groups (?>...)
and possessive quantifiers *+ ++ ?+, which forbid backtracking into what they
matched; or rewrite the pattern so each character can be matched only one
way, which also works in older engines and other languages. Cap input length
regardless. Times are machine-dependent, so each run gets a fixed budget in a
child process and the table prints "ok" or "exceeded" instead of seconds.
"""

import re
import subprocess
import sys

PATTERNS = {
    "noncompliant (\\w+\\s?)*": r"^(\w+\s?)*$",
    "compliant (?>\\w+\\s?)*": r"^(?>\w+\s?)*$",
    "compliant (\\w+\\s?)*+": r"^(\w+\s?)*+$",
    "compliant \\w+(\\s\\w+)*\\s?": r"^(?:\w+(?:\s\w+)*\s?)?$",
}
SIZES = (6, 12, 18, 36, 72)
BUDGET = 0.75  # seconds per match; 18 letters take milliseconds, 36 take hours
CHILD = "import re, sys; re.match(sys.argv[1], 'a' * int(sys.argv[2]) + '!')"
SAMPLES = ["", "hello", "hello world", "hello world ", "hello  world", "hello!", "a b c d"]


def run_with_budget(pattern: str, n: int) -> str:
    try:
        subprocess.run([sys.executable, "-I", "-c", CHILD, pattern, str(n)],
                       timeout=BUDGET, check=True)
    except subprocess.TimeoutExpired:
        return "exceeded"
    return "ok"


def main() -> None:
    print(f"{'pattern':26}" + "".join(f"{f'n={n}':>10}" for n in SIZES))
    for label, pattern in PATTERNS.items():
        cells, stop = [], False
        for n in SIZES:
            cells.append("-" if stop else run_with_budget(pattern, n))
            stop = stop or cells[-1] == "exceeded"   # longer inputs only get worse
        print(f"{label:26}" + "".join(f"{c:>10}" for c in cells))
    print()
    print("same verdicts on ordinary input (Y = matches):")
    print(f"{'input':16}" + "".join(f"{i:>4}" for i in range(1, len(PATTERNS) + 1)))
    for s in SAMPLES:
        row = "".join(f"{'Y' if re.match(p, s) else '.':>4}" for p in PATTERNS.values())
        print(f"{s!r:16}{row}")


if __name__ == "__main__":
    main()

# Output:
# pattern                          n=6      n=12      n=18      n=36      n=72
# noncompliant (\w+\s?)*            ok        ok        ok  exceeded         -
# compliant (?>\w+\s?)*             ok        ok        ok        ok        ok
# compliant (\w+\s?)*+              ok        ok        ok        ok        ok
# compliant \w+(\s\w+)*\s?          ok        ok        ok        ok        ok
#
# same verdicts on ordinary input (Y = matches):
# input              1   2   3   4
# ''                 Y   Y   Y   Y
# 'hello'            Y   Y   Y   Y
# 'hello world'      Y   Y   Y   Y
# 'hello world '     Y   Y   Y   Y
# 'hello  world'     .   .   .   .
# 'hello!'           .   .   .   .
# 'a b c d'          Y   Y   Y   Y
