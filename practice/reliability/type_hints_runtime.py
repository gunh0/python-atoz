"""Type hints are not checked at runtime — validate where data enters

https://docs.python.org/3/library/typing.html

Modern code is lavishly annotated, and annotations make code *look*
verified. CPython ignores them when the program runs: `def scale(port: int)`
happily receives "8080"; `user: User = json.loads(body)` with a TypedDict
checks nothing; `isinstance(obj, SomeProtocol)` on a @runtime_checkable
Protocol only checks that the method names exist, not their signatures or
return types. A type checker (mypy, pyright) helps inside your code, but it
cannot see JSON from the network, environment variables or CLI arguments.

So validate once at the boundary — parse untrusted input into checked values
and trust the types after that. The small validator below reads the
TypedDict's own annotations so the schema is written once.
"""

import json
from typing import Literal, Protocol, TypedDict, get_args, get_origin, get_type_hints, runtime_checkable


def next_port(port: int) -> int:
    return port + 1


class User(TypedDict):
    name: str
    age: int
    role: Literal["admin", "viewer"]
    groups: list[str]


@runtime_checkable
class Reader(Protocol):
    def read(self, size: int) -> bytes: ...


class BrokenReader:
    def read(self) -> str:  # wrong signature, wrong return type
        return "not bytes"


def check(value: object, hint: object, path: str, errors: list[str]) -> None:
    origin = get_origin(hint)
    if origin is Literal:
        if value not in get_args(hint):
            errors.append(f"{path}: {value!r} not one of {list(get_args(hint))}")
    elif origin is list:
        if not isinstance(value, list):
            errors.append(f"{path}: expected list, got {type(value).__name__}")
            return
        for i, item in enumerate(value):
            check(item, get_args(hint)[0], f"{path}[{i}]", errors)
    elif hint is int and isinstance(value, bool):
        errors.append(f"{path}: expected int, got bool")  # bool is a subclass of int
    elif isinstance(hint, type) and not isinstance(value, hint):
        errors.append(f"{path}: expected {hint.__name__}, got {type(value).__name__}")


def validate(schema: type, data: object) -> list[str]:
    if not isinstance(data, dict):
        return [f"expected object, got {type(data).__name__}"]
    hints = get_type_hints(schema)
    errors = [f"{key}: missing" for key in sorted(schema.__required_keys__ - data.keys())]
    errors += [f"{key}: unexpected field" for key in sorted(data.keys() - hints.keys())]
    for key in hints:
        if key in data:
            check(data[key], hints[key], key, errors)
    return errors


def main() -> None:
    try:
        next_port("8080")
    except TypeError as exc:
        print(f"next_port('8080')           -> no check at the call, fails inside: {exc}")

    body = '{"name": "mallory", "age": true, "role": "root", "groups": "wheel", "is_admin": 1}'
    user: User = json.loads(body)  # annotation only; nothing is verified
    print(f"user: User = json.loads()   -> accepted, role={user['role']!r} groups={user['groups']!r}")

    print(f"isinstance(BrokenReader(), Reader) -> {isinstance(BrokenReader(), Reader)}")
    print()

    print("compliant: validate(User, json.loads(body))")
    for error in validate(User, json.loads(body)):
        print(f"  - {error}")
    good = '{"name": "alice", "age": 34, "role": "viewer", "groups": ["ops", "oncall"]}'
    print(f"compliant: valid body        -> {validate(User, json.loads(good)) or 'ok'}")
    print(f"compliant: missing fields    -> {validate(User, {'name': 'bob'})}")


if __name__ == "__main__":
    main()

# Output:
# next_port('8080')           -> no check at the call, fails inside: can only concatenate str (not "int") to str
# user: User = json.loads()   -> accepted, role='root' groups='wheel'
# isinstance(BrokenReader(), Reader) -> True
#
# compliant: validate(User, json.loads(body))
#   - is_admin: unexpected field
#   - age: expected int, got bool
#   - role: 'root' not one of ['admin', 'viewer']
#   - groups: expected list, got str
# compliant: valid body        -> ok
# compliant: missing fields    -> ['age: missing', 'groups: missing', 'role: missing']
