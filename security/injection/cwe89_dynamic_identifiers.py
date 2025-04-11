"""CWE-89: ORDER BY and other identifiers cannot be bound — allow-list them

https://cwe.mitre.org/data/definitions/89.html

Placeholders bind values, not column names, table names or ASC/DESC. Write
`ORDER BY ?` and SQLite sorts by a constant string: no error, just unsorted
rows. So the sort parameter of a list endpoint is usually pasted in with an
f-string, and that is a full injection point even though the WHERE clause is
parameterised: an expression in ORDER BY turns the row order into a yes/no
oracle, and repeating the question extracts any value one character at a
time.

Map the user's choice through a dict of known column names and directions and
reject everything else. The user never supplies SQL text, only a key.
"""

import sqlite3
import string

SORT_COLUMNS = {"name": "name", "created": "created_at", "role": "role"}
DIRECTIONS = {"asc": "ASC", "desc": "DESC"}


def setup() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE users (name TEXT, role TEXT, created_at INTEGER);
        INSERT INTO users VALUES ('carol', 'user', 2), ('alice', 'admin', 3), ('bob', 'user', 1);
        CREATE TABLE api_keys (owner TEXT, key TEXT);
        INSERT INTO api_keys VALUES ('alice', 'sk-live-7Qx2');
    """)
    return db


def names(rows) -> list[str]:
    return [r[0] for r in rows]


def bound_identifier(db, column: str) -> list[str]:
    # Looks safe, silently does nothing: binds the *string* 'name', a constant.
    return names(db.execute("SELECT name FROM users ORDER BY ?", (column,)))


def noncompliant(db, sort: str) -> list[str]:
    sql = f"SELECT name FROM users WHERE role != ? ORDER BY {sort}"
    return names(db.execute(sql, ("nobody",)))


def blind_extract(db, length: int = 12) -> str:
    """Attacker: rows come back by name when the guess is right, by created_at otherwise."""
    by_name = noncompliant(db, "name")
    alphabet = string.ascii_letters + string.digits + "-_"
    found = ""
    for pos in range(1, length + 1):
        for ch in alphabet:
            guess = f"(SELECT substr(key, {pos}, 1) FROM api_keys) = '{ch}'"
            if noncompliant(db, f"CASE WHEN {guess} THEN name ELSE created_at END") == by_name:
                found += ch
                break
    return found


def compliant(db, sort: str, direction: str = "asc") -> list[str]:
    try:
        column, order = SORT_COLUMNS[sort], DIRECTIONS[direction.lower()]
    except KeyError:
        raise ValueError(f"unsupported sort {sort!r} {direction!r}") from None
    sql = f"SELECT name FROM users WHERE role != ? ORDER BY {column} {order}, name"
    return names(db.execute(sql, ("nobody",)))


def main() -> None:
    db = setup()
    print("ORDER BY ? with 'name'      ", bound_identifier(db, "name"), "(insertion order, not sorted)")
    print("ORDER BY ? with 'created_at'", bound_identifier(db, "created_at"))
    print()
    print("noncompliant sort=name      ", noncompliant(db, "name"))
    print("noncompliant sort=created_at", noncompliant(db, "created_at"))
    print("noncompliant blind oracle    api key =", blind_extract(db))
    print()
    print("compliant name asc          ", compliant(db, "name"))
    print("compliant created desc      ", compliant(db, "created", "DESC"))
    for evil in ("CASE WHEN 1 THEN name END", "name; DROP TABLE users", "password"):
        try:
            compliant(db, evil)
        except ValueError as exc:
            print("compliant rejects           ", exc)


if __name__ == "__main__":
    main()

# Output:
# ORDER BY ? with 'name'       ['carol', 'alice', 'bob'] (insertion order, not sorted)
# ORDER BY ? with 'created_at' ['carol', 'alice', 'bob']
#
# noncompliant sort=name       ['alice', 'bob', 'carol']
# noncompliant sort=created_at ['bob', 'carol', 'alice']
# noncompliant blind oracle    api key = sk-live-7Qx2
#
# compliant name asc           ['alice', 'bob', 'carol']
# compliant created desc       ['alice', 'carol', 'bob']
# compliant rejects            unsupported sort 'CASE WHEN 1 THEN name END' 'asc'
# compliant rejects            unsupported sort 'name; DROP TABLE users' 'asc'
# compliant rejects            unsupported sort 'password' 'asc'
