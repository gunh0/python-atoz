"""CWE-502: deserialization of untrusted data — pickle.loads runs code

https://cwe.mitre.org/data/definitions/502.html

pickle is not a data format, it is a small stack machine whose REDUCE opcode
calls any importable callable with arguments from the stream. A class only
needs __reduce__ to return (subprocess.check_output, (["id"],)) and the
*loader* runs the command, before your code sees any object. Session
cookies, cache entries in a shared Redis, "model files" and multiprocessing
endpoints are where this shows up. Signing the blob only moves the problem to
the signing key.

Use json (or another pure data format) and rebuild your objects from
validated fields. If you are stuck with pickle for compatibility, override
Unpickler.find_class with an explicit allow-list; that blocks the import,
which is what every gadget needs.
"""

import io
import json
import pickle
import pickletools
import subprocess
from dataclasses import asdict, dataclass


@dataclass
class Session:
    user: str
    roles: list[str]


class Exploit:
    def __reduce__(self):
        return (subprocess.check_output, (["echo", "INJECTED-by-pickle"],))


def noncompliant_load(blob: bytes):
    return pickle.loads(blob)


class AllowListUnpickler(pickle.Unpickler):
    ALLOWED = {("__main__", "Session")}

    def find_class(self, module, name):
        if (module, name) not in self.ALLOWED:
            raise pickle.UnpicklingError(f"blocked import {module}.{name}")
        return super().find_class(module, name)


def mitigated_load(blob: bytes):
    return AllowListUnpickler(io.BytesIO(blob)).load()


def compliant_load(text: str) -> Session:
    data = json.loads(text)
    if set(data) != {"user", "roles"} or not isinstance(data["user"], str) \
            or not all(isinstance(r, str) for r in data["roles"]):
        raise ValueError("bad session")
    return Session(data["user"], list(data["roles"]))


def attempt(fn, arg) -> str:
    try:
        return repr(fn(arg))
    except (pickle.UnpicklingError, ValueError) as exc:
        return f"{type(exc).__name__}: {exc}"


def _dis(blob: bytes) -> str:
    out = io.StringIO()
    pickletools.dis(pickletools.optimize(blob), out=out, annotate=0)
    return out.getvalue()


def main() -> None:
    good = pickle.dumps(Session("ada", ["user"]), protocol=4)
    evil = pickle.dumps(Exploit(), protocol=4)
    print("what the attacker's blob does (pickletools.dis):")
    for line in io.StringIO(_dis(evil)):
        print("  " + line.rstrip())
    print()
    print("noncompliant pickle.loads(good) ", attempt(noncompliant_load, good))
    print("noncompliant pickle.loads(evil) ", attempt(noncompliant_load, evil))
    print("mitigated allow-list(good)      ", attempt(mitigated_load, good))
    print("mitigated allow-list(evil)      ", attempt(mitigated_load, evil))
    good_json = json.dumps(asdict(Session("ada", ["user"])))
    print("compliant json(good)            ", attempt(compliant_load, good_json))
    print("compliant json(extra field)     ",
          attempt(compliant_load, '{"user": "ada", "roles": ["admin"], "__class__": "x"}'))


if __name__ == "__main__":
    main()

# Output:
# what the attacker's blob does (pickletools.dis):
#       0: \x80 PROTO      4
#       2: \x95 FRAME      59
#      11: \x8c SHORT_BINUNICODE 'subprocess'
#      23: \x8c SHORT_BINUNICODE 'check_output'
#      37: \x93 STACK_GLOBAL
#      38: ]    EMPTY_LIST
#      39: (    MARK
#      40: \x8c     SHORT_BINUNICODE 'echo'
#      46: \x8c     SHORT_BINUNICODE 'INJECTED-by-pickle'
#      66: e        APPENDS    (MARK at 39)
#      67: \x85 TUPLE1
#      68: R    REDUCE
#      69: .    STOP
#   highest protocol among opcodes = 4
#
# noncompliant pickle.loads(good)  Session(user='ada', roles=['user'])
# noncompliant pickle.loads(evil)  b'INJECTED-by-pickle\n'
# mitigated allow-list(good)       Session(user='ada', roles=['user'])
# mitigated allow-list(evil)       UnpicklingError: blocked import subprocess.check_output
# compliant json(good)             Session(user='ada', roles=['user'])
# compliant json(extra field)      ValueError: bad session
