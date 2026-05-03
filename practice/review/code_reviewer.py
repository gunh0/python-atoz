"""Code reviewer v4 — a report with locations, severities and a CI gate

https://docs.python.org/3/library/ast.html

v1–v3 collected rules; v4 makes the output something a reviewer and a CI job
can act on. Every finding carries file:line:col, a severity and the offending
source line, the report is sorted by location, and a summary decides the gate:
any HIGH finding fails the build (a CI wrapper would `sys.exit(gate(...))`).

A tool that cannot be silenced gets uninstalled, so v4 also honours an
explicit, rule-specific suppression on the same line —
`# review: ignore[REV001]` — and counts suppressions in the summary so they
stay visible in review. Code under review should earn its suppressions one by
one; there is deliberately no file-wide off switch.
"""

import ast
import re
from collections import Counter
from dataclasses import dataclass

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


RULES = {
    "REV001": "HIGH",    # eval/exec
    "REV002": "HIGH",    # shell=True, os.system
    "REV003": "MEDIUM",  # bare except
    "REV004": "MEDIUM",  # mutable default argument
    "REV005": "MEDIUM",  # assert used for validation
}
SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW")
IGNORE = re.compile(r"#\s*review:\s*ignore\[([A-Z0-9, ]+)\]")


@dataclass(frozen=True, order=True)
class Finding:
    line: int
    col: int
    rule: str
    message: str

    @property
    def severity(self) -> str:
        return RULES[self.rule]


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
        self.findings.append(Finding(node.lineno, node.col_offset + 1, rule, message))

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


def review(source: str) -> tuple[list[Finding], int]:
    """Return (findings, number of suppressed findings)."""
    reviewer = Reviewer()
    reviewer.visit(ast.parse(source))
    lines = source.splitlines()
    kept, suppressed = [], 0
    for finding in sorted(reviewer.findings):
        match = IGNORE.search(lines[finding.line - 1])
        if match and finding.rule in {r.strip() for r in match.group(1).split(",")}:
            suppressed += 1
        else:
            kept.append(finding)
    return kept, suppressed


def report(filename: str, source: str) -> int:
    findings, suppressed = review(source)
    lines = source.splitlines()
    for f in findings:
        print(f"{filename}:{f.line}:{f.col}: {f.severity:<6} {f.rule} {f.message}")
        print(f"    {lines[f.line - 1].strip()}")
    counts = Counter(f.severity for f in findings)
    status = gate(findings)
    print(f"{filename}: " + ", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITY_ORDER)
          + f", {suppressed} suppressed -> gate {'FAIL' if status else 'PASS'}")
    return status


def gate(findings: list[Finding]) -> int:
    return 1 if any(f.severity == "HIGH" for f in findings) else 0


# A second file, after a review pass.
REVIEWED = '''\
import subprocess


def ping(host):
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False)


def render(template, context):
    # Templates are shipped with the package, never user supplied.
    return eval(template, {}, context)  # review: ignore[REV001] trusted templates only


def add_tags(tag, tags=None):
    tags = [] if tags is None else tags
    tags.append(tag)
    return tags
'''


def main() -> None:
    statuses = [report("ops_helper.py", SAMPLE), report("reviewed.py", REVIEWED)]
    print(f"exit status for CI: {max(statuses)}")


if __name__ == "__main__":
    main()

# Output:
# ops_helper.py:9:12: HIGH   REV001 call to eval() runs arbitrary code
#     return eval(expression)
# ops_helper.py:14:5: HIGH   REV001 call to exec() runs arbitrary code
#     exec(source_code, namespace)
# ops_helper.py:19:12: HIGH   REV001 call to builtins.eval() runs arbitrary code
#     return builtins.eval(code)
# ops_helper.py:27:12: HIGH   REV002 subprocess.run(..., shell=True): pass an argument list instead
#     return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
# ops_helper.py:33:5: MEDIUM REV003 bare except: also catches KeyboardInterrupt/SystemExit
#     except:
# ops_helper.py:38:23: MEDIUM REV004 add_tag(): mutable default [] is shared between calls
#     def add_tag(tag, tags=[]):
# ops_helper.py:44:5: MEDIUM REV005 transfer(): assert amount > 0 is removed under python -O
#     assert amount > 0, "amount must be positive"
# ops_helper.py:45:5: MEDIUM REV005 transfer(): assert user.is_admin is removed under python -O
#     assert user.is_admin
# ops_helper.py: 4 high, 4 medium, 0 low, 0 suppressed -> gate FAIL
# reviewed.py: 0 high, 0 medium, 0 low, 1 suppressed -> gate PASS
# exit status for CI: 1
