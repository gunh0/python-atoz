# requires-python: >=3.14
"""Deferred annotations (PEP 649/749) — ``cls.__dict__["__annotations__"]`` is gone in 3.14

https://peps.python.org/pep-0649/   https://peps.python.org/pep-0749/

Python 3.14 evaluates annotations lazily. A class can now mention a type that
is defined later without quotes, and the class body stores an ``__annotate__``
function instead of an ``__annotations__`` dict. Older code, and code
copied from it, has tiny validators and serializers that read
``cls.__dict__.get("__annotations__", {})`` (old advice to avoid inheriting a
base class's annotations). On 3.14 that returns ``{}``: the validator checks
nothing and passes bad data. Separately, forward references no longer fail at
class creation; the ``NameError`` moves to whoever reads the annotations.

Review note: read annotations with ``annotationlib.get_annotations(cls)``
(own annotations only, like the old ``__dict__`` trick). Where names may not be
importable yet (``TYPE_CHECKING`` imports, plugins), pass
``format=Format.FORWARDREF`` or ``Format.STRING`` instead of catching
``NameError``.
"""

import annotationlib
from annotationlib import Format
from typing import TYPE_CHECKING

if TYPE_CHECKING:                  # common idiom: import only for the type checker
    from ipaddress import IPv4Address


class Model:
    id: int


class User(Model):
    name: str
    age: int
    manager: Manager | None        # defined further down; no quotes needed in 3.14
    last_ip: IPv4Address           # never defined at runtime


def own_fields_noncompliant(cls) -> dict:
    return cls.__dict__.get("__annotations__", {})


def own_fields_compliant(cls, fmt: Format = Format.VALUE) -> dict:
    return annotationlib.get_annotations(cls, format=fmt)


def validate(data: dict, fields: dict) -> list[str]:
    errors = []
    for name, tp in fields.items():
        if isinstance(tp, type) and not isinstance(data.get(name), tp):
            errors.append(f"{name}: expected {tp.__name__}, got {type(data.get(name)).__name__}")
    return errors


def describe(value) -> str:
    if isinstance(value, annotationlib.ForwardRef):
        return f"ForwardRef({value.__forward_arg__!r})"
    if isinstance(value, type):
        return value.__name__
    return str(value).replace("__main__.", "")


def main() -> None:
    bad = {"name": 42, "age": "forty", "manager": None}

    fields = own_fields_noncompliant(User)
    print("noncompliant: fields =", fields, " errors =", validate(bad, fields))
    print("'__annotations__' in User.__dict__:", "__annotations__" in User.__dict__,
          " callable(User.__annotate__):", callable(User.__annotate__))

    try:
        own_fields_compliant(User)
    except NameError as exc:
        print("get_annotations VALUE: NameError:", exc)

    fwd = own_fields_compliant(User, Format.FORWARDREF)
    print("compliant FORWARDREF:", {k: describe(v) for k, v in fwd.items()})
    print("compliant validate:  ", validate(bad, fwd))
    print("compliant STRING:    ", own_fields_compliant(User, Format.STRING))
    print("base field 'id' included:", "id" in fwd)


class Manager:
    pass


if __name__ == "__main__":
    main()

# Output:
# noncompliant: fields = {}  errors = []
# '__annotations__' in User.__dict__: False  callable(User.__annotate__): True
# get_annotations VALUE: NameError: name 'IPv4Address' is not defined
# compliant FORWARDREF: {'name': 'str', 'age': 'int', 'manager': 'Manager | None', 'last_ip': "ForwardRef('IPv4Address')"}
# compliant validate:   ['name: expected str, got int', 'age: expected int, got str']
# compliant STRING:     {'name': 'str', 'age': 'int', 'manager': 'Manager | None', 'last_ip': 'IPv4Address'}
# base field 'id' included: False
