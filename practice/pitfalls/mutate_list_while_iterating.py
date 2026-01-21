"""Mutating a list while iterating — items get skipped without any error

"Remove the expired sessions from the list" is commonly written as
``for s in sessions: if expired(s): sessions.remove(s)``. It reads like the
English sentence and works whenever expired items are not adjacent. The list
iterator walks by index; removing an element shifts the next one into the
current slot, and the loop steps past it. Dicts and sets at least raise
``RuntimeError`` when their size changes, lists say nothing.

Review note: never add or remove items of the collection you are looping
over. Build a new list with a comprehension (and assign back with
``items[:] = ...`` if other references must see it), iterate over a copy, or
iterate backwards by index when in-place deletion is really needed.
"""

SESSIONS = ["s1:expired", "s2:expired", "s3:ok", "s4:expired", "s5:expired", "s6:ok"]


def expired(s: str) -> bool:
    return s.endswith(":expired")


def purge_noncompliant(sessions: list[str]) -> list[str]:
    for s in sessions:
        if expired(s):
            sessions.remove(s)
    return sessions


def purge_compliant(sessions: list[str]) -> list[str]:
    sessions[:] = [s for s in sessions if not expired(s)]
    return sessions


def purge_compliant_reverse(sessions: list[str]) -> list[str]:
    for i in range(len(sessions) - 1, -1, -1):
        if expired(sessions[i]):
            del sessions[i]
    return sessions


def main() -> None:
    print("noncompliant:", purge_noncompliant(list(SESSIONS)))
    print("compliant:   ", purge_compliant(list(SESSIONS)))
    print("reverse del: ", purge_compliant_reverse(list(SESSIONS)))

    # Which elements did the noncompliant loop actually look at?
    seen = []
    items = list(SESSIONS)
    for s in items:
        seen.append(s.split(":")[0])
        if expired(s):
            items.remove(s)
    print("noncompliant loop visited:", seen)

    # Slicing assignment keeps other references in sync.
    sessions = list(SESSIONS)
    alias = sessions
    purge_compliant(sessions)
    print("alias sees the purge:", alias is sessions, alias)

    cache = {"a": 1, "b": 2}
    try:
        for key in cache:
            if cache[key] == 1:
                del cache[key]
    except RuntimeError as exc:
        print("dict:", type(exc).__name__ + ":", exc)


if __name__ == "__main__":
    main()

# Output:
# noncompliant: ['s2:expired', 's3:ok', 's5:expired', 's6:ok']
# compliant:    ['s3:ok', 's6:ok']
# reverse del:  ['s3:ok', 's6:ok']
# noncompliant loop visited: ['s1', 's3', 's4', 's6']
# alias sees the purge: True ['s3:ok', 's6:ok']
# dict: RuntimeError: dictionary changed size during iteration
