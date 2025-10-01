"""CWE-532: secrets leaking through repr — redact at the type, not at every call site

https://cwe.mitre.org/data/definitions/532.html

Nobody writes log.info(password). They write log.debug("config %r", cfg), raise
ValueError(f"bad settings: {cfg}"), or let an error tracker capture locals,
and a dataclass's generated __repr__ prints every field, password included.

Fix it where the value lives. field(repr=False) hides one field from the
dataclass repr, but asdict() and JSON still carry it. A small Secret wrapper
is stronger: repr and str are always redacted, json.dumps and pickle refuse it
instead of serialising it, comparison is constant-time, and the plaintext
needs an explicit .reveal() call that is easy to grep for in review.
"""

import dataclasses
import hmac
import json
import pickle


@dataclasses.dataclass
class NoncompliantConfig:
    host: str
    user: str
    password: str


@dataclasses.dataclass
class FieldHiddenConfig:
    host: str
    user: str
    password: str = dataclasses.field(repr=False)


class Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('***')"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other._value.encode())

    def __deepcopy__(self, memo: dict) -> "Secret":
        return self  # dataclasses.asdict() deep-copies fields; keep the wrapper intact

    def __reduce__(self):
        raise TypeError("Secret values are not picklable")  # no plaintext in caches or queues


@dataclasses.dataclass
class CompliantConfig:
    host: str
    user: str
    password: Secret


def show(label: str, cfg) -> None:
    print(f"{label} repr  {cfg!r}")
    print(f"{label} error {ValueError(f'cannot connect: {cfg}')}")
    try:
        print(f"{label} json  {json.dumps(dataclasses.asdict(cfg))}")
    except TypeError as exc:
        print(f"{label} json  refused: {exc}")


def main() -> None:
    show("noncompliant:", NoncompliantConfig("db.internal", "app", "S3cr3t!pw"))
    show("field-hidden:", FieldHiddenConfig("db.internal", "app", "S3cr3t!pw"))
    cfg = CompliantConfig("db.internal", "app", Secret("S3cr3t!pw"))
    show("compliant:   ", cfg)
    print(f"compliant:    f-string  password={cfg.password}")
    print(f"compliant:    equal     {cfg.password == Secret('S3cr3t!pw')}")
    try:
        pickle.dumps(cfg)
    except TypeError as exc:
        print(f"compliant:    pickle    refused: {exc}")
    print(f"compliant:    reveal    {len(cfg.password.reveal())} chars (only where the driver needs it)")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: repr  NoncompliantConfig(host='db.internal', user='app', password='S3cr3t!pw')
# noncompliant: error cannot connect: NoncompliantConfig(host='db.internal', user='app', password='S3cr3t!pw')
# noncompliant: json  {"host": "db.internal", "user": "app", "password": "S3cr3t!pw"}
# field-hidden: repr  FieldHiddenConfig(host='db.internal', user='app')
# field-hidden: error cannot connect: FieldHiddenConfig(host='db.internal', user='app')
# field-hidden: json  {"host": "db.internal", "user": "app", "password": "S3cr3t!pw"}
# compliant:    repr  CompliantConfig(host='db.internal', user='app', password=Secret('***'))
# compliant:    error cannot connect: CompliantConfig(host='db.internal', user='app', password=Secret('***'))
# compliant:    json  refused: Object of type Secret is not JSON serializable
# compliant:    f-string  password=Secret('***')
# compliant:    equal     True
# compliant:    pickle    refused: Secret values are not picklable
# compliant:    reveal    9 chars (only where the driver needs it)
