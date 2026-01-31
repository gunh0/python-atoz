"""Dataclass pitfalls — shared defaults, default_factory, and what frozen means

https://docs.python.org/3/library/dataclasses.html#mutable-default-values

`@dataclass` catches the obvious mistake: `tags: list = []` raises ValueError
when the class is defined. So the usual "fix" goes one of two ways that
still share state: it moves the list to a plain class attribute, or it uses a
default object that happens to be hashable (any ordinary class instance is),
which dataclasses cannot detect. Every instance then shares one object.

The fix is `field(default_factory=...)`, which builds a fresh value per
instance. `frozen=True` stops attribute assignment, not mutation of what the
attributes point to: a frozen dataclass holding a list is still mutable and
not even hashable. Use tuples/frozensets inside frozen classes and
`dataclasses.replace()` to derive changed copies.
"""

from dataclasses import FrozenInstanceError, dataclass, field, replace


def rejected_at_definition() -> str:
    try:
        @dataclass
        class Job:
            tags: list = []
    except ValueError as exc:
        return str(exc)
    return "accepted"


class JobPlain:  # the "fix" that moves the list out of the dataclass machinery
    tags: list = []

    def __init__(self, name: str) -> None:
        self.name = name


class RetryPolicy:
    def __init__(self) -> None:
        self.attempts = 3


@dataclass
class ClientNoncompliant:
    name: str
    retry: RetryPolicy = RetryPolicy()  # hashable instance: allowed, and shared


@dataclass
class ClientCompliant:
    name: str
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RuleFrozenList:
    name: str
    ports: list[int]


@dataclass(frozen=True)
class Rule:
    name: str
    ports: tuple[int, ...] = ()


def main() -> None:
    print(f"tags: list = []       -> ValueError: {rejected_at_definition()}")

    a, b = JobPlain("backup"), JobPlain("rotate")
    a.tags.append("nightly")
    print(f"noncompliant: class attribute list      -> b.tags = {b.tags}")

    a, b = ClientNoncompliant("billing"), ClientNoncompliant("search")
    a.retry.attempts = 10
    print(f"noncompliant: RetryPolicy() default     -> b.retry.attempts = {b.retry.attempts}, "
          f"same object: {a.retry is b.retry}")

    a, b = ClientCompliant("billing"), ClientCompliant("search")
    a.retry.attempts = 10
    a.tags.append("pci")
    print(f"compliant:    field(default_factory=..) -> b.retry.attempts = {b.retry.attempts}, "
          f"b.tags = {b.tags}")
    print()

    rule = RuleFrozenList("web", [80, 443])
    try:
        rule.name = "db"
    except FrozenInstanceError as exc:
        print(f"frozen: rule.name = 'db'    -> FrozenInstanceError: {exc}")
    rule.ports.append(22)
    print(f"frozen: rule.ports.append() -> still works, ports = {rule.ports}")
    try:
        hash(rule)
    except TypeError as exc:
        print(f"frozen: hash(rule)          -> TypeError: {exc}")

    rule = Rule("web", (80, 443))
    ssh = replace(rule, name="web+ssh", ports=rule.ports + (22,))
    print(f"compliant:  replace()       -> {ssh}, original untouched: {rule.ports}")
    print(f"compliant:  usable as key   -> {len({rule: 'allow', ssh: 'review'})} entries")


if __name__ == "__main__":
    main()

# Output:
# tags: list = []       -> ValueError: mutable default <class 'list'> for field tags is not allowed: use default_factory
# noncompliant: class attribute list      -> b.tags = ['nightly']
# noncompliant: RetryPolicy() default     -> b.retry.attempts = 10, same object: True
# compliant:    field(default_factory=..) -> b.retry.attempts = 3, b.tags = []
#
# frozen: rule.name = 'db'    -> FrozenInstanceError: cannot assign to field 'name'
# frozen: rule.ports.append() -> still works, ports = [80, 443, 22]
# frozen: hash(rule)          -> TypeError: unhashable type: 'list'
# compliant:  replace()       -> Rule(name='web+ssh', ports=(80, 443, 22)), original untouched: (80, 443)
# compliant:  usable as key   -> 2 entries
