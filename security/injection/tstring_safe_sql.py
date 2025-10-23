# requires-python: >=3.14
"""CWE-89 with PEP 750 template strings: t"..." keeps values out of the SQL text

https://cwe.mitre.org/data/definitions/89.html   (https://peps.python.org/pep-0750/)

The f-string is the most natural way to write a query and the most common
SQL injection (cwe89_sql_injection). Python 3.14 adds t-strings: t"... {x}"
looks the same but evaluates to a string.templatelib.Template holding the
literal parts and the interpolated values *separately*. A query helper that
accepts only Template can turn each value into a ? placeholder and pass the
values as parameters, so the convenient spelling is also the safe one, and
a plain str (an f-string someone wrote by habit) is refused with TypeError.

The helper below also covers what placeholders cannot bind (see
cwe89_dynamic_identifiers): an interpolation with the format spec ":ident"
must name an allow-listed column and is emitted as a quoted identifier. Nested templates
compose, so WHERE fragments can be built separately and stay safe.
"""

import sqlite3
from string.templatelib import Interpolation, Template

IDENTIFIERS = {"name", "role", "created_at"}


def sql(query: Template) -> tuple[str, list]:
    if not isinstance(query, Template):
        raise TypeError(f"sql() takes a t-string, not {type(query).__name__}")
    text, params = [], []
    for part in query:
        if isinstance(part, str):
            text.append(part)
        elif isinstance(part.value, Template):          # nested fragment
            sub_text, sub_params = sql(part.value)
            text.append(sub_text)
            params += sub_params
        elif part.format_spec == "ident":
            if part.value not in IDENTIFIERS:
                raise ValueError(f"identifier {part.value!r} not allowed")
            text.append(f'"{part.value}"')
        elif part.conversion or part.format_spec:
            raise ValueError(f"no conversions or format specs on SQL values: {{{part.expression}}}")
        else:
            text.append("?")
            params.append(part.value)
    return "".join(text), params


def setup() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE users (name TEXT, role TEXT, created_at INTEGER, password TEXT);
        INSERT INTO users VALUES ('alice', 'admin', 3, 'wonderland'), ('bob', 'user', 1, 'builder');
    """)
    return db


def noncompliant(db, name: str):
    return db.execute(f"SELECT name, role FROM users WHERE name = '{name}'").fetchall()


def compliant(db, name: str, order: str = "name"):
    query, params = sql(t"SELECT name, role FROM users WHERE name = {name} ORDER BY {order:ident}")
    return db.execute(query, params).fetchall()


def attempt(fn, *args):
    try:
        return fn(*args)
    except (TypeError, ValueError, sqlite3.Error) as exc:
        return f"{type(exc).__name__}: {exc}"


def main() -> None:
    db = setup()
    evil = "x' OR '1'='1"
    union = "x' UNION SELECT name, password FROM users --"
    print("noncompliant f-string 'alice'  ", attempt(noncompliant, db, "alice"))
    print("noncompliant f-string OR 1=1   ", attempt(noncompliant, db, evil))
    print("noncompliant f-string UNION    ", attempt(noncompliant, db, union))
    print("compliant t-string 'alice'     ", attempt(compliant, db, "alice"))
    print("compliant t-string OR 1=1      ", attempt(compliant, db, evil))
    print("compliant t-string UNION       ", attempt(compliant, db, union))
    print("compliant ORDER BY password    ", attempt(compliant, db, "alice", "password"))
    print()
    role = "user"
    where = t"role = {role} AND created_at > {0}"
    print("rendered nested:", sql(t"SELECT name FROM users WHERE {where} ORDER BY {'created_at':ident}"))
    print("rendered !r:    ", attempt(sql, t"SELECT {evil!r}"))
    print("plain str:      ", attempt(sql, f"SELECT * FROM users WHERE name = '{evil}'"))


if __name__ == "__main__":
    main()

# Output:
# noncompliant f-string 'alice'   [('alice', 'admin')]
# noncompliant f-string OR 1=1    [('alice', 'admin'), ('bob', 'user')]
# noncompliant f-string UNION     [('alice', 'wonderland'), ('bob', 'builder')]
# compliant t-string 'alice'      [('alice', 'admin')]
# compliant t-string OR 1=1       []
# compliant t-string UNION        []
# compliant ORDER BY password     ValueError: identifier 'password' not allowed
#
# rendered nested: ('SELECT name FROM users WHERE role = ? AND created_at > ? ORDER BY "created_at"', ['user', 0])
# rendered !r:     ValueError: no conversions or format specs on SQL values: {evil}
# plain str:       TypeError: sql() takes a t-string, not str
