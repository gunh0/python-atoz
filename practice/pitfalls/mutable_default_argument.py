"""Mutable default arguments — the default is evaluated once, not per call

A common way to write "a helper that collects audit events" is
``def record(event, log=[])``. It reads naturally and the first call in a quick
test works, so it survives review. The catch: the default list is created once,
when the ``def`` statement runs, and every call that omits ``log`` shares that
same object. State leaks between requests, users or test cases.

Review note: any ``=[]``, ``={}``, ``=set()`` or ``=SomeClass()`` in a
signature is a finding. Use ``None`` as the default and build the object inside
the function. ``__defaults__`` shows you the shared object directly.
"""


def record_noncompliant(event: str, log: list[str] = []) -> list[str]:  # noqa: B006
    log.append(event)
    return log


def record_compliant(event: str, log: list[str] | None = None) -> list[str]:
    if log is None:
        log = []
    log.append(event)
    return log


def main() -> None:
    # Two unrelated "requests" that each expect a fresh log.
    alice = record_noncompliant("alice: login")
    bob = record_noncompliant("bob: login")
    print("noncompliant: bob's log =", bob)
    print("noncompliant: same object for alice and bob:", alice is bob)
    print("noncompliant: __defaults__ now =", record_noncompliant.__defaults__)

    alice = record_compliant("alice: login")
    bob = record_compliant("bob: login")
    print("compliant:    bob's log =", bob)
    print("compliant:    same object for alice and bob:", alice is bob)
    print("compliant:    __defaults__ now =", record_compliant.__defaults__)

    # Passing a list explicitly still works the same in both versions.
    shared = ["boot"]
    record_compliant("alice: login", shared)
    print("compliant:    explicit log =", shared)


if __name__ == "__main__":
    main()

# Output:
# noncompliant: bob's log = ['alice: login', 'bob: login']
# noncompliant: same object for alice and bob: True
# noncompliant: __defaults__ now = (['alice: login', 'bob: login'],)
# compliant:    bob's log = ['bob: login']
# compliant:    same object for alice and bob: False
# compliant:    __defaults__ now = (None,)
# compliant:    explicit log = ['boot', 'alice: login']
