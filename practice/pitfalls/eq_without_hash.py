"""``__eq__`` without ``__hash__`` — unhashable objects, or worse, a hash that changes

A value class typically gets an ``__eq__`` so ``==`` compares fields.
Python then sets ``__hash__ = None``: instances can no longer go into a set or
be dict keys, and the error appears far away from the class. The typical
"fix" is to add ``__hash__`` over the same mutable fields. Now an object that
is mutated after being added to a set lands in the wrong bucket: ``in``
returns False for an object that is physically in the set, and the set can
hold two "equal" items.

Review note: define ``__hash__`` only for immutable values, and derive it
from exactly the fields ``__eq__`` uses. The easy, correct route is
``@dataclass(frozen=True)``. If the object must stay mutable, key the set or
dict by an immutable id instead of the object itself.
"""

from dataclasses import dataclass


class EndpointEqOnly:
    def __init__(self, host: str, port: int):
        self.host, self.port = host, port

    def __eq__(self, other):
        return isinstance(other, EndpointEqOnly) and (self.host, self.port) == (other.host, other.port)


class EndpointMutableHash(EndpointEqOnly):
    def __hash__(self):
        return hash((self.host, self.port))


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int


def main() -> None:
    print("EndpointEqOnly.__hash__ is None:", EndpointEqOnly.__hash__ is None)
    try:
        {EndpointEqOnly("127.0.0.1", 8080)}
    except TypeError as exc:
        # The message wording changed in 3.14; the type and the cause did not.
        print("noncompliant (eq only):", type(exc).__name__, "unhashable:", "unhashable type" in str(exc))

    ep = EndpointMutableHash("127.0.0.1", 8080)
    seen = {ep}
    ep.port = 8443                      # mutated after insertion
    print("noncompliant (mutable hash): ep in seen ->", ep in seen,
          " any(x is ep) ->", any(x is ep for x in seen))
    seen.add(ep)
    print("noncompliant (mutable hash): len(seen) after re-adding the same object ->", len(seen))

    frozen = Endpoint("127.0.0.1", 8080)
    pool = {frozen, Endpoint("127.0.0.1", 8080)}
    print("compliant (frozen dataclass): len(pool) =", len(pool),
          " lookup ->", Endpoint("127.0.0.1", 8080) in pool)
    try:
        frozen.port = 8443
    except AttributeError as exc:
        print("compliant: mutation blocked ->", type(exc).__name__)


if __name__ == "__main__":
    main()

# Output:
# EndpointEqOnly.__hash__ is None: True
# noncompliant (eq only): TypeError unhashable: True
# noncompliant (mutable hash): ep in seen -> False  any(x is ep) -> True
# noncompliant (mutable hash): len(seen) after re-adding the same object -> 2
# compliant (frozen dataclass): len(pool) = 1  lookup -> True
# compliant: mutation blocked -> FrozenInstanceError
