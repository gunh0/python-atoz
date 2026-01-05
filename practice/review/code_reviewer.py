"""Code reviewer v3 — mutable default arguments and `assert` as validation

https://docs.python.org/3/reference/compound_stmts.html#function-definitions
https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement

Two Python-specific mistakes that are easy to make with a straight face:

`def add_tag(tag, tags=[])` — the default list is created once, when the
function is defined, and shared by every call. The second caller sees the
first caller's tags. Use `None` and create the list inside.

`assert amount > 0, "amount must be positive"` as input validation — asserts
are removed when Python runs with `-O` (some container images and packagers do
this), so the check silently disappears. Raise ValueError/PermissionError for
validation; keep assert for internal invariants and tests. v3 flags asserts
outside `test_*` functions and demonstrates both bugs actually happening.
"""

import ast
import subprocess
import sys

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
MUTABLE_CALLS = {"list", "dict", "set", "bytearray", "defaultdict", "deque"}


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
        self.functions: list[str] = []  # enclosing function names

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

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for default in node.args.defaults + [d for d in node.args.kw_defaults if d]:
            literal = isinstance(default, (ast.List, ast.Dict, ast.Set))
            factory = isinstance(default, ast.Call) and dotted(default.func)[-1:] in {
                (name,) for name in MUTABLE_CALLS}
            if literal or factory:
                self.report(default, "REV004", f"{node.name}(): mutable default "
                                               f"{ast.unparse(default)} is shared between calls")
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assert(self, node: ast.Assert) -> None:
        where = self.functions[-1] if self.functions else "<module>"
        if not where.startswith("test"):
            self.report(node, "REV005", f"{where}(): assert {ast.unparse(node.test)} "
                                        "is removed under python -O")
        self.generic_visit(node)


def review(source: str) -> list[Finding]:
    reviewer = Reviewer()
    reviewer.visit(ast.parse(source))
    return sorted(reviewer.findings)


def show_bugs() -> None:
    namespace: dict = {}
    exec(compile(SAMPLE, "<sample>", "exec"), namespace)  # our own fixture, not user input
    add_tag = namespace["add_tag"]
    add_tag("prod")
    second = add_tag("db")
    print(f"add_tag('prod') then add_tag('db') -> second call returned {second}")

    probe = SAMPLE + "\nprint(transfer(-500, type('U', (), {'is_admin': False})()))\n"
    for label, flags in (("python   ", []), ("python -O", ["-O"])):
        run = subprocess.run([sys.executable, *flags, "-c", probe], capture_output=True, text=True)
        outcome = run.stdout.strip() or run.stderr.strip().splitlines()[-1]
        print(f"{label} transfer(-500, non-admin) -> {outcome}")


def main() -> None:
    findings = review(SAMPLE)
    print(f"reviewer v3: {len(findings)} findings")
    for line, rule, message in findings:
        print(f"  {line:>3} {rule}: {message}")
    print()
    show_bugs()


if __name__ == "__main__":
    main()

# Output:
# reviewer v3: 8 findings
#     9 REV001: call to eval() runs arbitrary code
#    14 REV001: call to exec() runs arbitrary code
#    19 REV001: call to builtins.eval() runs arbitrary code
#    27 REV002: subprocess.run(..., shell=True): pass an argument list instead
#    33 REV003: bare except: also catches KeyboardInterrupt/SystemExit
#    38 REV004: add_tag(): mutable default [] is shared between calls
#    44 REV005: transfer(): assert amount > 0 is removed under python -O
#    45 REV005: transfer(): assert user.is_admin is removed under python -O
#
# add_tag('prod') then add_tag('db') -> second call returned ['prod', 'db']
# python    transfer(-500, non-admin) -> AssertionError: amount must be positive
# python -O transfer(-500, non-admin) -> -500
