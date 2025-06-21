"""CWE-95: eval() with empty __builtins__ is not a sandbox

https://cwe.mitre.org/data/definitions/95.html

Follow-up to cwe95_eval_vs_literal_eval: a calculator endpoint needs
arithmetic, which literal_eval refuses, so someone writes
eval(expr, {"__builtins__": {}}) and a blocklist for "__" and "import". Both
fall over. Every object still knows its class, every class reaches `object`,
and object.__subclasses__() lists every loaded class, including os._wrap_close
whose __init__.__globals__ *is* the os module namespace. The "__" check is
beaten by Unicode: identifiers are NFKC-normalised, so "_＿class_＿" (with a
FULLWIDTH LOW LINE) is the same name as "__class__", and a word blocklist
falls to mathematical letters such as "𝗀lobals".

The fix is not a better blocklist but a grammar you control: parse with
ast.parse(mode="eval"), walk the tree, allow only the node types you mean
(numbers and + - * / ** here) and cap the sizes that can blow up.
"""

import ast
import operator
import os

OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
       ast.Div: operator.truediv, ast.Pow: operator.pow, ast.USub: operator.neg}
MAX_EXPONENT = 100
ESCAPE = ("[c for c in ().__class__.__base__.__subclasses__()"
          " if c.__name__ == '_wrap_close'][0].__init__.__globals__['environ']['APP_SECRET']")
INPUTS = [
    "2 * (3 + 4) - 1",
    ESCAPE,
    ESCAPE.replace("__", "_\uff3f"),  # "_＿": no "__" substring, same identifier after NFKC
    ESCAPE.replace("__", "_\uff3f")     # plus MATHEMATICAL SANS-SERIF SMALL S and G
          .replace("subclasses", "\U0001d5ccubclasses").replace("globals", "\U0001d5c0lobals"),
    "9 ** 9 ** 9",
]


def noncompliant_no_builtins(expr: str):
    return eval(expr, {"__builtins__": {}}, {})


def noncompliant_blocklist(expr: str):
    if any(bad in expr for bad in ("__", "import", "subclasses", "globals")):
        raise ValueError("blocked by blocklist")
    return eval(expr, {"__builtins__": {}}, {})


def compliant(expr: str):
    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.UnaryOp) and type(node.op) in OPS:
            return OPS[type(node.op)](ev(node.operand))
        if isinstance(node, ast.BinOp) and type(node.op) in OPS:
            left, right = ev(node.left), ev(node.right)
            if isinstance(node.op, ast.Pow) and abs(right) > MAX_EXPONENT:
                raise ValueError(f"exponent {right} over limit")
            return OPS[type(node.op)](left, right)
        raise ValueError(f"{type(node).__name__} not allowed")

    if len(expr) > 200:
        raise ValueError("expression too long")
    return ev(ast.parse(expr, mode="eval"))


def attempt(fn, expr: str) -> str:
    try:
        return repr(fn(expr))
    except (ValueError, AttributeError, SyntaxError) as exc:
        return f"{type(exc).__name__}: {exc}"


def main() -> None:
    os.environ["APP_SECRET"] = "s3cr3t-db-password"
    for expr in INPUTS:
        print(f"expr {expr if len(expr) < 50 else expr[:47] + '...'!r}")
        if "9 ** 9" in expr:  # would compute for a very long time: that is the point
            print("  noncompliant both:        (not run: 9**9**9 has 370 million digits)")
        else:
            print(f"  noncompliant no builtins: {attempt(noncompliant_no_builtins, expr)}")
            print(f"  noncompliant blocklist:   {attempt(noncompliant_blocklist, expr)}")
        print(f"  compliant ast walker:     {attempt(compliant, expr)}")


if __name__ == "__main__":
    main()

# Output:
# expr '2 * (3 + 4) - 1'
#   noncompliant no builtins: 13
#   noncompliant blocklist:   13
#   compliant ast walker:     13
# expr '[c for c in ().__class__.__base__.__subclasses_...'
#   noncompliant no builtins: 's3cr3t-db-password'
#   noncompliant blocklist:   ValueError: blocked by blocklist
#   compliant ast walker:     ValueError: Subscript not allowed
# expr '[c for c in ()._＿class_＿._＿base_＿._＿subclasses_...'
#   noncompliant no builtins: 's3cr3t-db-password'
#   noncompliant blocklist:   ValueError: blocked by blocklist
#   compliant ast walker:     ValueError: Subscript not allowed
# expr '[c for c in ()._＿class_＿._＿base_＿._＿𝗌ubclasses_...'
#   noncompliant no builtins: 's3cr3t-db-password'
#   noncompliant blocklist:   's3cr3t-db-password'
#   compliant ast walker:     ValueError: Subscript not allowed
# expr '9 ** 9 ** 9'
#   noncompliant both:        (not run: 9**9**9 has 370 million digits)
#   compliant ast walker:     ValueError: exponent 387420489 over limit
