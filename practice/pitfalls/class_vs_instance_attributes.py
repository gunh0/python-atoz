"""Class vs instance attributes — a list on the class is shared by every instance

A small data class is often written with Java-style field
declarations in the class body: ``class Host: tags = []``. Reading
``self.tags`` finds the class attribute, ``self.tags.append(...)`` mutates it in
place, and every host now carries every other host's tags. Assignment
(``self.count = self.count + 1``) behaves differently: it creates an instance
attribute that shadows the class one, so integers seem to "work", which makes
the list case even more surprising.

Review note: mutable state belongs in ``__init__`` (or in a dataclass with
``field(default_factory=list)``; dataclasses refuse ``= []`` outright). Class
attributes are fine for constants and for values that are meant to be shared,
and should be annotated ``ClassVar`` so the intent is visible.
"""

from dataclasses import dataclass, field
from typing import ClassVar


class HostNoncompliant:
    tags = []          # shared by all instances
    checks = 0

    def __init__(self, name: str):
        self.name = name

    def tag(self, t: str) -> None:
        self.tags.append(t)
        self.checks += 1   # creates an instance attribute: looks fine


class HostCompliant:
    default_port: ClassVar[int] = 22   # a real, shared constant

    def __init__(self, name: str):
        self.name = name
        self.tags: list[str] = []


@dataclass
class HostRecord:
    name: str
    tags: list[str] = field(default_factory=list)


def main() -> None:
    web, db = HostNoncompliant("web01"), HostNoncompliant("db01")
    web.tag("nginx")
    db.tag("postgres")
    print("noncompliant: web.tags =", web.tags, " db.tags =", db.tags)
    print("noncompliant: tags in instance __dict__?", "tags" in vars(web),
          " checks in instance __dict__?", "checks" in vars(web))

    web, db = HostCompliant("web01"), HostCompliant("db01")
    web.tags.append("nginx")
    db.tags.append("postgres")
    print("compliant:    web.tags =", web.tags, " db.tags =", db.tags)

    a, b = HostRecord("web01"), HostRecord("db01")
    a.tags.append("nginx")
    print("dataclass:    ", a, b)

    try:
        @dataclass
        class Broken:
            tags: list = []
    except ValueError as exc:
        print("dataclass with `= []`:", type(exc).__name__ + ":", exc)


if __name__ == "__main__":
    main()

# Output:
# noncompliant: web.tags = ['nginx', 'postgres']  db.tags = ['nginx', 'postgres']
# noncompliant: tags in instance __dict__? False  checks in instance __dict__? True
# compliant:    web.tags = ['nginx']  db.tags = ['postgres']
# dataclass:     HostRecord(name='web01', tags=['nginx']) HostRecord(name='db01', tags=[])
# dataclass with `= []`: ValueError: mutable default <class 'list'> for field tags is not allowed: use default_factory
