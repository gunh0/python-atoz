"""vmstat report v3 — grouped header with merged cells, column widths, real dates

v2's sheet was correct but looked like a CSV: narrow columns cut off the
timestamps, eleven flat headers, and times stored as text that Excel cannot
put on a chart axis. v3 adds the parts that make it a report:

- row 1 groups the columns (procs, memory, swap, cpu) with <mergeCells>
- <cols> sets each column width from the longest value in it
- xl/styles.xml defines bold header styles and a "yyyy-mm-dd hh:mm:ss"
  number format; the time column is written as an Excel serial date (days
  since 1899-12-30) using that format, so it sorts and charts as a time
- <sheetViews> freezes the two header rows while scrolling

Element order inside <worksheet> is fixed by the schema (sheetViews, cols,
sheetData, mergeCells); Excel reports a damaged file if it is wrong, so the
writer emits them in that order. Reading back checks merges, widths and that
the date survives the round trip.
"""

import csv
import io
import tempfile
import zipfile
import xml.etree.ElementTree as ET
import datetime as dt
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
GROUPS = [  # header row 1; must cover FIELDS in order
    ("", 1), ("procs", 2), ("memory (MiB)", 2), ("swap (KiB/s)", 2), ("cpu (%)", 4),
]
EXCEL_EPOCH = dt.datetime(1899, 12, 30)  # serial 0; skips Lotus's fake 1900-02-29


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
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""

ROOT_RELS = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{PKG_REL_NS}">
<Relationship Id="rId1" Type="{REL_NS}/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

WORKBOOK_RELS = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{PKG_REL_NS}">
<Relationship Id="rId1" Type="{REL_NS}/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="{REL_NS}/styles" Target="styles.xml"/>
</Relationships>"""

# cellXfs indexes used by cell(): 0 default, 1 group header, 2 column header, 3 date-time
STYLE_GROUP, STYLE_HEADER, STYLE_DATETIME = 1, 2, 3
STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="{NS}">
<numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm:ss"/></numFmts>
<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>
<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="4">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""


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


def cell(ref: str, value, style: int = 0) -> str:
    s = f' s="{style}"' if style else ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}"{s}><v>{value}</v></c>'
    return f'<c r="{ref}"{s} t="inlineStr"><is><t>{escape(str(value))}</t></is></c>'


def excel_serial(text: str) -> float:
    """'2026-03-14 10:00:05 UTC' -> days since 1899-12-30 (the UTC suffix is dropped)."""
    when = dt.datetime.fromisoformat(text.removesuffix(" UTC"))
    return (when - EXCEL_EPOCH) / dt.timedelta(days=1)


def from_serial(serial: float) -> dt.datetime:
    return EXCEL_EPOCH + dt.timedelta(seconds=round(serial * 86400))


def sheet_xml(records: list[dict]) -> str:
    rows: list[list[str]] = []
    row1, merges, col = [], [], 0
    for title, span in GROUPS:
        row1.append(cell(f"{column_letter(col)}1", title, STYLE_GROUP))
        if span > 1:
            merges.append(f"{column_letter(col)}1:{column_letter(col + span - 1)}1")
        col += span
    assert col == len(FIELDS), "GROUPS must cover every field"
    rows.append(row1)
    rows.append([cell(f"{column_letter(c)}2", name, STYLE_HEADER) for c, name in enumerate(FIELDS)])
    for r, rec in enumerate(records, start=3):
        line = [cell(f"A{r}", excel_serial(rec["time"]), STYLE_DATETIME)]
        line += [cell(f"{column_letter(c)}{r}", rec[f]) for c, f in enumerate(FIELDS) if c]
        rows.append(line)

    widths = [20] + [max(len(f), *(len(str(rec[f])) for rec in records)) + 2 for f in FIELDS[1:]]
    cols = "".join(f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>' for i, w in enumerate(widths, 1))
    views = ('<sheetViews><sheetView workbookViewId="0">'
             '<pane ySplit="2" topLeftCell="A3" activePane="bottomLeft" state="frozen"/>'
             '</sheetView></sheetViews>')
    data = "".join(f'<row r="{r}">{"".join(cells)}</row>' for r, cells in enumerate(rows, start=1))
    merge_xml = f'<mergeCells count="{len(merges)}">' + "".join(
        f'<mergeCell ref="{m}"/>' for m in merges) + "</mergeCells>"
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<worksheet xmlns="{NS}">'
            f"{views}<cols>{cols}</cols><sheetData>{data}</sheetData>{merge_xml}</worksheet>")


def write_xlsx(records: list[dict], path: Path, sheet_name: str) -> None:
    parts = {
        "[Content_Types].xml": CONTENT_TYPES,
        "_rels/.rels": ROOT_RELS,
        "xl/workbook.xml": workbook_xml(sheet_name),
        "xl/_rels/workbook.xml.rels": WORKBOOK_RELS,
        "xl/styles.xml": STYLES,
        "xl/worksheets/sheet1.xml": sheet_xml(records),
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, xml in parts.items():
            zf.writestr(name, xml)


def read_xlsx(path: Path) -> dict:
    """Read back what a reviewer would check: cells, styles, merges, widths."""
    ns = {"m": NS}
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        sheet = ET.fromstring(zf.read("xl/worksheets/sheet1.xml"))
        styles = ET.fromstring(zf.read("xl/styles.xml"))
    formats = {f.get("numFmtId"): f.get("formatCode") for f in styles.iter(f"{{{NS}}}numFmt")}
    xfs = [xf.get("numFmtId") for xf in styles.find("m:cellXfs", ns)]
    cells, cell_format = {}, {}
    for c in sheet.iter(f"{{{NS}}}c"):
        ref = c.get("r")
        node = c.find("m:is/m:t", ns) if c.get("t") == "inlineStr" else c.find("m:v", ns)
        cells[ref] = node.text or ""
        cell_format[ref] = formats.get(xfs[int(c.get("s", "0"))], "General")
    return {
        "parts": names,
        "cells": cells,
        "format": cell_format,
        "merged": [m.get("ref") for m in sheet.iter(f"{{{NS}}}mergeCell")],
        "widths": [float(c.get("width")) for c in sheet.iter(f"{{{NS}}}col")],
        "frozen": sheet.find("m:sheetViews/m:sheetView/m:pane", ns).get("topLeftCell"),
    }


def main() -> None:
    records = [to_record(v) for v in parse(VMSTAT_T_SAMPLE)]
    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / "vmstat-web-01.csv"
        xlsx_path = Path(tmp) / "vmstat-web-01.xlsx"
        write_csv(records, csv_path)
        write_xlsx(records, xlsx_path, sheet_name="web-01 & db-01")
        back = list(csv.DictReader(io.StringIO(csv_path.read_text(encoding="utf-8"), newline="")))
        book = read_xlsx(xlsx_path)

    print(f"csv:  {len(back)} rows, round trip intact: {[r['time'] for r in back] == [r['time'] for r in records]}")
    print(f"xlsx: {len(book['parts'])} parts: {', '.join(book['parts'])}")
    print("merged header cells:", ", ".join(book["merged"]))
    print("row 1:", " | ".join(book["cells"][f"{column_letter(c)}1"] or "(blank)" for c in (0, 1, 3, 5, 7)))
    print("row 2:", " | ".join(book["cells"][f"{column_letter(c)}2"] for c in range(len(FIELDS))))
    print("column widths:", " ".join(f"{column_letter(i)}={w:g}" for i, w in enumerate(book["widths"])))
    print("frozen panes, first scrolling cell:", book["frozen"])
    a3 = book["cells"]["A3"]
    print(f"A3 stored as {a3} with format {book['format']['A3']!r} -> {from_serial(float(a3))}")
    print(f"K3 stored as {book['cells']['K3']} with format {book['format']['K3']!r}")


if __name__ == "__main__":
    main()

# Output:
# csv:  5 rows, round trip intact: True
# xlsx: 6 parts: [Content_Types].xml, _rels/.rels, xl/workbook.xml, xl/_rels/workbook.xml.rels, xl/styles.xml, xl/worksheets/sheet1.xml
# merged header cells: B1:C1, D1:E1, F1:G1, H1:K1
# row 1: (blank) | procs | memory (MiB) | swap (KiB/s) | cpu (%)
# row 2: time | run_queue | blocked | free_mib | cache_mib | swap_in | swap_out | cpu_user | cpu_system | cpu_iowait | cpu_busy
# column widths: A=20 B=11 C=9 D=10 E=11 F=9 G=10 H=10 I=12 J=12 K=10
# frozen panes, first scrolling cell: A3
# A3 stored as 46095.41672453703 with format 'yyyy-mm-dd hh:mm:ss' -> 2026-03-14 10:00:05
# K3 stored as 39 with format 'General'
