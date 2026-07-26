r"""CWE-20: input validation — an allow-list regex is only as strict as its anchors

https://cwe.mitre.org/data/definitions/20.html

Validating with an allow-list is right; the details of Python's re decide
whether it holds. re.match() anchors only the start, so "web01;id" passes
[a-z0-9-]+. "$" also matches just before a trailing newline, so "web01\n"
passes ^...$ and the newline reaches a config file or header. \w and \d are
Unicode-aware for str patterns: Arabic-Indic digits and fullwidth letters
are "word characters". re.IGNORECASE folds Unicode too, so [a-z] matches the
KELVIN SIGN and LATIN SMALL LETTER LONG S. str.isalnum()/isdigit() have the
same Unicode breadth.

Use re.fullmatch() with an explicit ASCII character class, no IGNORECASE
(lower-case the input first if you want case-insensitivity, then validate the
result), and a length bound in the pattern. Validate the exact string you
will use, after every transformation.
"""

import re

HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

CHECKS = {
    "match":     lambda s: bool(re.match(r"[a-z0-9-]+", s)),
    "^$":        lambda s: bool(re.match(r"^[a-z0-9-]+$", s)),
    "^$ re.I":   lambda s: bool(re.match(r"^[a-z0-9-]+$", s, re.IGNORECASE)),
    r"\w+":      lambda s: bool(re.fullmatch(r"\w+", s)),
    "isalnum":   str.isalnum,
    "compliant": lambda s: bool(HOSTNAME.fullmatch(s)),
}
INPUTS = ["web01", "web-01", "web01;id", "web01\n", "\u212aube", "\u017fsh",
          "\u0661\u0662\u0663", "\uff57\uff45\uff42", "w\xe9b", "-web", "a" * 64]


def main() -> None:
    print(f"{'input':22}" + "".join(f"{name:>10}" for name in CHECKS))
    for s in INPUTS:
        label = ascii(s) if len(s) < 20 else f"'a' * {len(s)}"   # ascii(): show \u escapes
        print(f"{label:22}" + "".join(f"{'pass' if fn(s) else '.':>10}" for fn in CHECKS.values()))
    print()
    kelvin = "\u212aube"
    print(f"{ascii(kelvin)}.lower() == 'kube': {kelvin.lower() == 'kube'}  (validate after lower(), not before)")
    print(f"compliant on lower()ed value: {bool(HOSTNAME.fullmatch(kelvin.lower()))}")


if __name__ == "__main__":
    main()

# Output:
# input                      match        ^$   ^$ re.I       \w+   isalnum compliant
# 'web01'                     pass      pass      pass      pass      pass      pass
# 'web-01'                    pass      pass      pass         .         .      pass
# 'web01;id'                  pass         .         .         .         .         .
# 'web01\n'                   pass      pass      pass         .         .         .
# '\u212aube'                    .         .      pass      pass      pass         .
# '\u017fsh'                     .         .      pass      pass      pass         .
# '\u0661\u0662\u0663'           .         .         .      pass      pass         .
# '\uff57\uff45\uff42'           .         .         .      pass      pass         .
# 'w\xe9b'                    pass         .         .      pass      pass         .
# '-web'                      pass      pass      pass         .         .         .
# 'a' * 64                    pass      pass      pass      pass      pass         .
#
# '\u212aube'.lower() == 'kube': True  (validate after lower(), not before)
# compliant on lower()ed value: True
