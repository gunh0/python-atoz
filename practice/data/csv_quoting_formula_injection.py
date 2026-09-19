"""CSV quoting and formula injection — ``",".join(row)`` is not CSV

https://owasp.org/www-community/attacks/CSV_Injection

"Export the users to CSV" is often written as ``",".join(fields)``. The first
customer named "Kim, Jiwoo" or a note with a newline shifts every column after
it. Using the ``csv`` module fixes the quoting, but not the second problem: a
spreadsheet treats cells starting with ``=``, ``+``, ``-``, ``@`` (and tab or CR)
as formulas. A user-controlled display name like ``=HYPERLINK(...)`` becomes a
clickable phishing link, or worse, in the admin's Excel.

Review note: write with ``csv.writer`` (open files with ``newline=""``), and
neutralize user-controlled *text* cells that start with a formula character by
prefixing a single quote. Leave real numbers as numbers. The output below uses
``lineterminator="\\n"`` only to keep the printed example readable; the
module default ``"\\r\\n"`` is what RFC 4180 asks for.
"""

import csv
import io

ROWS = [
    ["id", "name", "note"],
    [1, "Kim, Jiwoo", 'said "hi"'],
    [2, "Lee", "line one\nline two"],
    [3, '=HYPERLINK("http://evil.example/login","Reset password")', "-"],
    [4, "+82 10 1234 5678", -12.5],
]

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def export_noncompliant(rows) -> str:
    return "\n".join(",".join(str(v) for v in row) for row in rows) + "\n"


def neutralize(value):
    if isinstance(value, str) and value.startswith(FORMULA_START):
        return "'" + value
    return value


def export_compliant(rows) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    for row in rows:
        writer.writerow([neutralize(v) for v in row])
    return buf.getvalue()


def main() -> None:
    bad = export_noncompliant(ROWS)
    print("noncompliant output:")
    print(bad, end="")
    print("noncompliant parsed column counts:", [len(r) for r in csv.reader(io.StringIO(bad))])

    good = export_compliant(ROWS)
    print()
    print("compliant output:")
    print(good, end="")
    parsed = list(csv.reader(io.StringIO(good)))
    print("compliant parsed column counts:   ", [len(r) for r in parsed])
    print("row 2 note round-trips:", parsed[2][2] == ROWS[2][2])
    print("row 3 name starts with:", repr(parsed[3][1][:2]), "(rendered as text, not a formula)")


if __name__ == "__main__":
    main()

# Output:
# noncompliant output:
# id,name,note
# 1,Kim, Jiwoo,said "hi"
# 2,Lee,line one
# line two
# 3,=HYPERLINK("http://evil.example/login","Reset password"),-
# 4,+82 10 1234 5678,-12.5
# noncompliant parsed column counts: [3, 4, 3, 1, 4, 3]
#
# compliant output:
# id,name,note
# 1,"Kim, Jiwoo","said ""hi"""
# 2,Lee,"line one
# line two"
# 3,"'=HYPERLINK(""http://evil.example/login"",""Reset password"")",'-
# 4,'+82 10 1234 5678,-12.5
# compliant parsed column counts:    [3, 3, 3, 3, 3]
# row 2 note round-trips: True
# row 3 name starts with: "'=" (rendered as text, not a formula)
