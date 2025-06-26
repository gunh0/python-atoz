"""Code reviewer v2 — add rules for shell=True and bare `except:`

https://cwe.mitre.org/data/definitions/78.html
https://cwe.mitre.org/data/definitions/396.html

v1 found eval/exec. The next two things that show up in nearly every batch of
ops code I review are `subprocess.run(f"ping {host}", shell=True)` — command
injection as soon as `host` comes from a user — and `try: ... except:` that
swallows everything, including KeyboardInterrupt, SystemExit and the very bug
the reviewer is looking for. An f-string makes `shell=True` look tidy; the bare
except makes a flaky function look robust.

v2 turns the single visitor into small rules with IDs so each finding says
which policy it violates. `os.system`/`os.popen` always use a shell and are
flagged too; `shell=False` and `except Exception` are left alone here.
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


Finding = tuple[int, str, str]  # (line, rule id, message)

DANGEROUS = {"eval", "exec"}
SHELL_FUNCS = {("os", "system"), ("os", "popen")}


def dotted(node: ast.expr) -> tuple[str, ...]:
    """`subprocess.run` -> ("subprocess", "run"); anything else -> ()."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


class Reviewer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def report(self, node: ast.AST, rule: str, message: str) -> None:
        self.findings.append((node.lineno, rule, message))

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted(node.func)
        if name in {(n,) for n in DANGEROUS} | {("builtins", n) for n in DANGEROUS}:
            self.report(node, "REV001", f"call to {'.'.join(name)}() runs arbitrary code")
        for kw in node.keywords:
            if (kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True):
                self.report(node, "REV002", f"{'.'.join(name) or 'call'}(..., shell=True): "
                                            "pass an argument list instead")
        if name in SHELL_FUNCS:
            self.report(node, "REV002", f"{'.'.join(name)}() always runs a shell")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.report(node, "REV003", "bare except: also catches KeyboardInterrupt/SystemExit")
        self.generic_visit(node)


def review(source: str) -> list[Finding]:
    reviewer = Reviewer()
    reviewer.visit(ast.parse(source))
    return sorted(reviewer.findings)


def main() -> None:
    findings = review(SAMPLE)
    print(f"reviewer v2: {len(findings)} findings")
    for line, rule, message in findings:
        print(f"  {line:>3} {rule}: {message}")

    snippets = {
        "os.system backup": "import os\nos.system('tar czf /backup/site.tgz ' + path)\n",
        "argument list": "import subprocess\nsubprocess.run(['ping', '-c', '1', host], check=True)\n",
    }
    for label, code in snippets.items():
        found = review(code)
        print(f"{label + ':':<18} {len(found)} findings {[rule for _, rule, _ in found]}")


if __name__ == "__main__":
    main()

# Output:
# reviewer v2: 5 findings
#     9 REV001: call to eval() runs arbitrary code
#    14 REV001: call to exec() runs arbitrary code
#    19 REV001: call to builtins.eval() runs arbitrary code
#    27 REV002: subprocess.run(..., shell=True): pass an argument list instead
#    33 REV003: bare except: also catches KeyboardInterrupt/SystemExit
# os.system backup:  1 findings ['REV002']
# argument list:     0 findings []
