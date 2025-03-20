"""CWE-89: SQL injection — bind values with placeholders, never format them in

https://cwe.mitre.org/data/definitions/89.html

An f-string query mixes code and data: a quote in the input closes the string
literal and the rest is parsed as SQL. The classics still work against
sqlite3: a tautology that logs in without a password, and a UNION that reads
a table the query never mentioned. sqlite3's execute() refuses a second
statement, which stops "; DROP TABLE" but nothing else.

With ? (or :name) placeholders the driver sends the value separately from the
statement, so it can only ever be compared as data. One leftover: a value
bound into LIKE still treats % and _ as wildcards, so escape them and declare
ESCAPE when users search by substring.
"""

import sqlite3


def setup() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE users (name TEXT, password TEXT, role TEXT);
        INSERT INTO users VALUES ('alice', 'wonderland', 'admin'),
                                 ('bob', 'builder', 'user');
        CREATE TABLE api_keys (owner TEXT, key TEXT);
        INSERT INTO api_keys VALUES ('alice', 'sk-live-ALICE-0001');
    """)
    return db


def noncompliant_login(db, name: str, password: str):
    sql = f"SELECT name, role FROM users WHERE name = '{name}' AND password = '{password}'"
    return db.execute(sql).fetchall()


def noncompliant_search(db, term: str):
    sql = f"SELECT name FROM users WHERE name LIKE '%{term}%'"
    return db.execute(sql).fetchall()


def compliant_login(db, name: str, password: str):
    sql = "SELECT name, role FROM users WHERE name = ? AND password = ?"
    return db.execute(sql, (name, password)).fetchall()


def escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def compliant_search(db, term: str, *, escape: bool = True):
    sql = "SELECT name FROM users WHERE name LIKE :pat ESCAPE '\\'"
    pat = f"%{escape_like(term) if escape else term}%"
    return db.execute(sql, {"pat": pat}).fetchall()


def attempt(fn, *args):
    try:
        return fn(*args)
    except sqlite3.Error as exc:
        return f"{type(exc).__name__}: {exc}"


def main() -> None:
    db = setup()
    tautology = ("alice' --", "anything")
    or_true = ("x", "' OR '1'='1")
    union = "zz' UNION SELECT key FROM api_keys --"
    stacked = "x'; DROP TABLE users; --"

    print("noncompliant login alice' --       ", attempt(noncompliant_login, db, *tautology))
    print("noncompliant login ' OR '1'='1     ", attempt(noncompliant_login, db, *or_true))
    print("noncompliant search UNION          ", attempt(noncompliant_search, db, union))
    print("noncompliant search stacked DROP   ", attempt(noncompliant_search, db, stacked))
    print()
    print("compliant login alice/wonderland   ", compliant_login(db, "alice", "wonderland"))
    print("compliant login alice' --          ", compliant_login(db, *tautology))
    print("compliant login ' OR '1'='1        ", compliant_login(db, *or_true))
    print("compliant search UNION             ", compliant_search(db, union))
    print("compliant search 'li'              ", compliant_search(db, "li"))
    print("bound but unescaped search '_'     ", compliant_search(db, "_", escape=False))
    print("compliant search '_'               ", compliant_search(db, "_"))
    print("users table still there            ", db.execute("SELECT count(*) FROM users").fetchone())


if __name__ == "__main__":
    main()

# Output:
# noncompliant login alice' --        [('alice', 'admin')]
# noncompliant login ' OR '1'='1      [('alice', 'admin'), ('bob', 'user')]
# noncompliant search UNION           [('sk-live-ALICE-0001',)]
# noncompliant search stacked DROP    ProgrammingError: You can only execute one statement at a time.
#
# compliant login alice/wonderland    [('alice', 'admin')]
# compliant login alice' --           []
# compliant login ' OR '1'='1         []
# compliant search UNION              []
# compliant search 'li'               [('alice',)]
# bound but unescaped search '_'      [('alice',), ('bob',)]
# compliant search '_'                []
# users table still there             (2,)
