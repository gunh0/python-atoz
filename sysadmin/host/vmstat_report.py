"""vmstat report v2 — also write a real .xlsx by hand with zipfile and XML

The CSV from v1 opens in Excel, but people asked for "a proper spreadsheet"
(numbers as numbers, no import dialog, one file to attach). You do not need
a third-party library for that. An .xlsx file is a zip archive of XML parts
(Office Open XML, ECMA-376), and a valid workbook needs only five of them:

    [Content_Types].xml         which part is which MIME type
    _rels/.rels                 points at the workbook
    xl/workbook.xml             the list of sheets
    xl/_rels/workbook.xml.rels  points at each sheet
    xl/worksheets/sheet1.xml    the cells

Strings are written as inline strings (t="inlineStr"), which avoids the
shared-string table; numbers are written as <v> values so Excel can sum
and chart them. Text goes through an XML escaper, because a hostname or a
process name with "&" or "<" otherwise produces a file Excel refuses to
open. The proof is reading the file back with zipfile and ElementTree.
"""

import csv
import io
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

VMSTAT_T_SAMPLE = """\
procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu----- -----timestamp-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st                 UTC
 1  0      0 1843212 120344 9120040    0    0     4    18   52   70  4  1 94  1  0 2026-03-14 10:00:00
 3  0      0 1801344 120352 9131200    0    0    12   340 1820 3120 31  6 61  2  0 2026-03-14 10:00:05
 6  1      0 1722008 120360 9150124    0    0   120   912 2930 5544 58 11 27  4  0 2026-03-14 10:00:10
 7  2      0 1690120 120360 9161004    0    0   844  1640 3310 6012 64 12 15  9  0 2026-03-14 10:00:15
 4  0      0 1754420 120368 9158220    0    0    40   420 2102 3901 40  8 50  2  0 2026-03-14 10:00:20
 2  0      0 1798004 120368 9159000    0    0     8   210 1544 2870 22  5 72  1  0 2026-03-14 10:00:25
"""

FIELDS = ["time", "run_queue", "blocked", "free_mib", "cache_mib", "swap_in", "swap_out",
          "cpu_user", "cpu_system", "cpu_iowait", "cpu_busy"]


def parse(text: str) -> list[dict]:
    lines = text.splitlines()
    names = lines[1].split()[:-1]  # last header word is the timezone of the timestamp
    tz = lines[1].split()[-1]
    rows = []
    for line in lines[3:]:  # lines[2] is the since-boot average
        parts = line.split()
        values = dict(zip(names, map(int, parts[: len(names)])))
        values["time"] = " ".join(parts[len(names):]) + f" {tz}"
        rows.append(values)
    return rows


def to_record(v: dict) -> dict:
    return {
        "time": v["time"],
        "run_queue": v["r"],
        "blocked": v["b"],
        "free_mib": round(v["free"] / 1024, 1),
        "cache_mib": round(v["cache"] / 1024, 1),
        "swap_in": v["si"],
        "swap_out": v["so"],
        "cpu_user": v["us"],
        "cpu_system": v["sy"],
        "cpu_iowait": v["wa"],
        "cpu_busy": 100 - v["id"],
    }


def write_csv(records: list[dict], path: Path) -> None:
    # newline="" lets the csv module write its own \r\n terminators unchanged
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)


NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"""

ROOT_RELS = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{PKG_REL_NS}">
<Relationship Id="rId1" Type="{REL_NS}/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

WORKBOOK_RELS = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{PKG_REL_NS}">
<Relationship Id="rId1" Type="{REL_NS}/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"""


def workbook_xml(sheet_name: str) -> str:
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<workbook xmlns="{NS}" xmlns:r="{REL_NS}"><sheets>'
            f'<sheet name={quoteattr(sheet_name)} sheetId="1" r:id="rId1"/>'
            f'</sheets></workbook>')


def column_letter(index: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA."""
    letters = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        letters = chr(ord("A") + rem) + letters
    return letters


def cell(ref: str, value) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}"><v>{value}</v></c>'
    return f'<c r="{ref}" t="inlineStr"><is><t>{escape(str(value))}</t></is></c>'


def sheet_xml(rows: list[list]) -> str:
    out = [f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<worksheet xmlns="{NS}"><sheetData>']
    for r, row in enumerate(rows, start=1):
        cells = "".join(cell(f"{column_letter(c)}{r}", v) for c, v in enumerate(row))
        out.append(f'<row r="{r}">{cells}</row>')
    out.append("</sheetData></worksheet>")
    return "".join(out)


def write_xlsx(records: list[dict], path: Path, sheet_name: str) -> None:
    rows = [FIELDS] + [[rec[f] for f in FIELDS] for rec in records]
    parts = {
        "[Content_Types].xml": CONTENT_TYPES,
        "_rels/.rels": ROOT_RELS,
        "xl/workbook.xml": workbook_xml(sheet_name),
        "xl/_rels/workbook.xml.rels": WORKBOOK_RELS,
        "xl/worksheets/sheet1.xml": sheet_xml(rows),
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, xml in parts.items():
            zf.writestr(name, xml)


def read_xlsx(path: Path) -> tuple[list[str], str, dict[str, str]]:
    """Return (part names, sheet name, {cell ref: value as text})."""
    ns = {"m": NS}
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        sheet = ET.fromstring(zf.read("xl/workbook.xml")).find("m:sheets/m:sheet", ns).get("name")
        root = ET.fromstring(zf.read("xl/worksheets/sheet1.xml"))
    cells = {}
    for c in root.iter(f"{{{NS}}}c"):
        if c.get("t") == "inlineStr":
            cells[c.get("r")] = c.find("m:is/m:t", ns).text
        else:
            cells[c.get("r")] = c.find("m:v", ns).text
    return names, sheet, cells


def main() -> None:
    records = [to_record(v) for v in parse(VMSTAT_T_SAMPLE)]
    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / "vmstat-web-01.csv"
        xlsx_path = Path(tmp) / "vmstat-web-01.xlsx"
        write_csv(records, csv_path)
        write_xlsx(records, xlsx_path, sheet_name="web-01 & db-01")
        back = list(csv.DictReader(io.StringIO(csv_path.read_text(encoding="utf-8"), newline="")))
        names, sheet, cells = read_xlsx(xlsx_path)
        is_zip = zipfile.is_zipfile(xlsx_path)

    print(f"csv:  {len(back)} rows, round trip intact: {[r['time'] for r in back] == [r['time'] for r in records]}")
    print(f"xlsx: zip archive {is_zip}, {len(names)} parts, sheet {sheet!r}")
    for name in names:
        print(f"      {name}")
    last_col = column_letter(len(FIELDS) - 1)
    print(f"cells read back: {len(cells)} (A1:{last_col}{len(records) + 1})")
    for r in range(1, 4):
        print(f"  row {r}: " + " | ".join(cells[f"{column_letter(c)}{r}"] for c in (0, 1, 3, 10)))
    print("column letters:", ", ".join(f"{i}->{column_letter(i)}" for i in (0, 10, 25, 26, 701, 702)))


if __name__ == "__main__":
    main()

# Output:
# csv:  5 rows, round trip intact: True
# xlsx: zip archive True, 5 parts, sheet 'web-01 & db-01'
#       [Content_Types].xml
#       _rels/.rels
#       xl/workbook.xml
#       xl/_rels/workbook.xml.rels
#       xl/worksheets/sheet1.xml
# cells read back: 66 (A1:K6)
#   row 1: time | run_queue | free_mib | cpu_busy
#   row 2: 2026-03-14 10:00:05 UTC | 3 | 1759.1 | 39
#   row 3: 2026-03-14 10:00:10 UTC | 6 | 1681.6 | 73
# column letters: 0->A, 10->K, 25->Z, 26->AA, 701->ZZ, 702->AAA
