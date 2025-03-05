"""Code reviewer v1 — parse the code with `ast` and flag eval/exec

https://cwe.mitre.org/data/definitions/95.html

Code that is fluent and confidently commented is exactly the code that
slips through review. "Evaluate a math expression from the form" becomes
`eval(expression)`; "load a plugin" becomes `exec(source)`. Both run arbitrary
code chosen by whoever controls the string.

Grepping for "eval" is noisy: it hits `ast.literal_eval`, `model.eval()` and
comments. Walking the syntax tree lets the reviewer match only real calls to
the builtins. This first version finds `eval`/`exec` called by name or via
`builtins.`; later versions add more rules and a proper report.
"""

import ast

# Sample code under review: a small ops helper service, written the common way.
SAMPLE = '''\
"""Small ops helper service."""
import ast
import builtins
import subprocess


def calculate(expression):
    # Evaluate a math expression from the web form
    return eval(expression)


def load_plugin(source_code):
    namespace = {}
    exec(source_code, namespace)
    return namespace


def run_snippet(code):
    return builtins.eval(code)


def parse_literal(text):
    return ast.literal_eval(text)


def ping(host):
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)


def disk_usage(path):
    try:
        out = subprocess.check_output(["du", "-sh", path])
    except:
        return None
    return out


def add_tag(tag, tags=[]):
    tags.append(tag)
    return tags


def transfer(amount, user):
    assert amount > 0, "amount must be positive"
    assert user.is_admin
    return amount


def predict(model, batch):
    model.eval()  # switch to inference mode
    return model(batch)
'''

DANGEROUS = {"eval", "exec"}


def grep_review(source: str) -> list[int]:
    """What a quick text search finds: every line mentioning eval/exec."""
    return [n for n, line in enumerate(source.splitlines(), 1)
            if any(word in line for word in DANGEROUS)]


class Reviewer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = None
        if isinstance(func, ast.Name) and func.id in DANGEROUS:
            name = func.id
        elif (isinstance(func, ast.Attribute) and func.attr in DANGEROUS
              and isinstance(func.value, ast.Name) and func.value.id == "builtins"):
            name = f"builtins.{func.attr}"
        if name:
            self.findings.append((node.lineno, f"call to {name}() runs arbitrary code"))
        self.generic_visit(node)


def review(source: str) -> list[tuple[int, str]]:
    reviewer = Reviewer()
    reviewer.visit(ast.parse(source))
    return reviewer.findings


def main() -> None:
    lines = SAMPLE.splitlines()
    hits = grep_review(SAMPLE)
    print(f"grep:     {len(hits)} lines mention eval/exec")
    for n in hits:
        print(f"  {n:>3}: {lines[n - 1].strip()}")
    print()
    findings = review(SAMPLE)
    print(f"reviewer: {len(findings)} findings")
    for n, message in findings:
        print(f"  {n:>3}: {message}")


if __name__ == "__main__":
    main()

# Output:
# grep:     5 lines mention eval/exec
#     9: return eval(expression)
#    14: exec(source_code, namespace)
#    19: return builtins.eval(code)
#    23: return ast.literal_eval(text)
#    50: model.eval()  # switch to inference mode
#
# reviewer: 3 findings
#     9: call to eval() runs arbitrary code
#    14: call to exec() runs arbitrary code
#    19: call to builtins.eval() runs arbitrary code
