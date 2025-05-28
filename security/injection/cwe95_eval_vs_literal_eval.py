"""CWE-95: eval injection — parse data with ast.literal_eval or json, never eval

https://cwe.mitre.org/data/definitions/95.html   (CWE-94: code injection)

eval() is the quick way to turn "[1, 2, 3]" from a query string or a config
value back into a list, and it runs whatever Python the string contains: read
secrets from the environment, write files, spawn processes. exec() is the same
for statements. There is no input validation that makes eval() safe (see the
follow-up unit on "restricted" globals).

ast.literal_eval() parses the string and accepts only literal nodes: str,
bytes, numbers, tuples, lists, dicts, sets, True/False/None (plus the +/-
needed for complex numbers). Anything else, including names, calls,
attribute access and arithmetic, raises ValueError before it runs. If the
format is yours to choose, prefer json.loads(), which is not even Python.
Keep a length cap either way: deep nesting raises SyntaxError or RecursionError.
"""

import ast
import json
import os
import tempfile
from pathlib import Path

MAX_LEN = 4096
INPUTS = [
    "[1, 2, 3]",
    "{'retries': 3, 'hosts': ('a', 'b'), 'debug': False}",
    "__import__('os').environ['APP_SECRET']",
    "open('pwned.txt', 'w').write('INJECTED')",
    "[x for x in ().__class__.__mro__]",
    "2 ** 10",
    "[" * 300 + "]" * 300,
]


def noncompliant(text: str):
    return eval(text)


def compliant(text: str):
    if len(text) > MAX_LEN:
        raise ValueError("input too long")
    return ast.literal_eval(text)


def compliant_json(text: str):
    return json.loads(text)


def attempt(fn, text: str) -> str:
    try:
        return repr(fn(text))
    except (ValueError, SyntaxError, RecursionError, NameError) as exc:
        reason = "malformed node" if str(exc).startswith("malformed node") else str(exc).split(" (")[0]
        return f"{type(exc).__name__}: {reason}"


def run_in_sandbox_dir(fn, text: str) -> str:
    """Run one parse in a fresh empty directory and report any file it dropped."""
    with tempfile.TemporaryDirectory() as tmp:
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            result = attempt(fn, text)[:56]
            dropped = sorted(p.name for p in Path(".").iterdir())
        finally:
            os.chdir(cwd)
    return result + (f"  [wrote {', '.join(dropped)}]" if dropped else "")


def main() -> None:
    os.environ["APP_SECRET"] = "s3cr3t-db-password"
    for text in INPUTS:
        print(f"input {text[:48]!r}")
        print(f"  noncompliant eval: {run_in_sandbox_dir(noncompliant, text)}")
        print(f"  compliant literal: {run_in_sandbox_dir(compliant, text)}")
    print()
    print("json.loads('[1, 2, 3]')       ", attempt(compliant_json, "[1, 2, 3]"))
    print("json.loads('{\"retries\": 3}')  ", attempt(compliant_json, '{"retries": 3}'))
    print("json.loads(\"__import__('os')\")", attempt(compliant_json, "__import__('os')").split(":")[0])


if __name__ == "__main__":
    main()

# Output:
# input '[1, 2, 3]'
#   noncompliant eval: [1, 2, 3]
#   compliant literal: [1, 2, 3]
# input "{'retries': 3, 'hosts': ('a', 'b'), 'debug': Fal"
#   noncompliant eval: {'retries': 3, 'hosts': ('a', 'b'), 'debug': False}
#   compliant literal: {'retries': 3, 'hosts': ('a', 'b'), 'debug': False}
# input "__import__('os').environ['APP_SECRET']"
#   noncompliant eval: 's3cr3t-db-password'
#   compliant literal: ValueError: malformed node
# input "open('pwned.txt', 'w').write('INJECTED')"
#   noncompliant eval: 8  [wrote pwned.txt]
#   compliant literal: ValueError: malformed node
# input '[x for x in ().__class__.__mro__]'
#   noncompliant eval: [<class 'tuple'>, <class 'object'>]
#   compliant literal: ValueError: malformed node
# input '2 ** 10'
#   noncompliant eval: 1024
#   compliant literal: ValueError: malformed node
# input '[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[['
#   noncompliant eval: SyntaxError: too many nested parentheses
#   compliant literal: SyntaxError: too many nested parentheses
#
# json.loads('[1, 2, 3]')        [1, 2, 3]
# json.loads('{"retries": 3}')   {'retries': 3}
# json.loads("__import__('os')") JSONDecodeError
