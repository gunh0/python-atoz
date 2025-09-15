"""str vs bytes and encodings — errors=, BOMs, and byte limits

Typical code for "read the uploaded CSV" or "store the name in a
VARCHAR(10) column" treats text and bytes as interchangeable:
``data.decode("latin-1")`` because it "never fails", ``errors="ignore"`` to
silence a traceback, ``len(name)`` as a byte limit, ``raw[:10].decode()`` to
truncate. Each of these runs without an error on ASCII test data and corrupts
real data: mojibake, silently dropped characters, a header key that is
``"\\ufeffid"`` instead of ``"id"`` because Excel wrote a UTF-8 BOM.

Review note: decode once, at the edge, with the encoding the producer
documents, and keep ``errors="strict"`` unless there is a written reason.
Read spreadsheet exports with ``utf-8-sig``. Enforce byte limits on the
encoded form and cut on character boundaries.
"""

import codecs
import csv
import io

UPLOAD = "id,name\n1,José\n2,Ærøskøbing\n".encode("utf-8-sig")  # Excel "CSV UTF-8"


def read_ids_noncompliant(raw: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(raw.decode("utf-8"))))


def read_ids_compliant(raw: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))


def truncate_noncompliant(text: str, max_bytes: int) -> str:
    return text[:max_bytes]                     # counts characters, not bytes


def truncate_compliant(text: str, max_bytes: int) -> str:
    out, used = [], 0
    for ch in text:
        size = len(ch.encode("utf-8"))
        if used + size > max_bytes:
            break
        out.append(ch)
        used += size
    return "".join(out)


def main() -> None:
    print("upload starts with BOM:", UPLOAD.startswith(codecs.BOM_UTF8))
    bad = read_ids_noncompliant(UPLOAD)
    print("noncompliant header keys:", list(bad[0]))
    print("noncompliant row['id']:", bad[0].get("id"))
    good = read_ids_compliant(UPLOAD)
    print("compliant header keys:   ", list(good[0]))
    print("compliant row['id']:   ", good[0]["id"])

    name = "José"
    raw = name.encode("utf-8")
    print(f"len(str)={len(name)}  len(bytes)={len(raw)}  bytes={raw!r}")
    print("decode as latin-1 (never fails):", raw.decode("latin-1"))
    for errors in ("strict", "replace", "ignore", "backslashreplace"):
        try:
            print(f"decode ascii errors={errors!r:<18}", repr(raw.decode("ascii", errors=errors)))
        except UnicodeDecodeError as exc:
            print(f"decode ascii errors={errors!r:<18} UnicodeDecodeError: {exc.reason} at {exc.start}")

    city, limit = "Ærøskøbing", 4
    try:
        city.encode("utf-8")[:limit].decode("utf-8")
    except UnicodeDecodeError as exc:
        print(f"raw[:{limit}].decode() ->", type(exc).__name__ + ":", exc.reason)
    for label, func in (("noncompliant", truncate_noncompliant), ("compliant", truncate_compliant)):
        cut = func(city, limit)
        print(f"{label + ':':<13} cut to {limit} bytes -> {cut!r:<10} "
              f"{len(cut.encode('utf-8'))} bytes, fits: {len(cut.encode('utf-8')) <= limit}")


if __name__ == "__main__":
    main()

# Output:
# upload starts with BOM: True
# noncompliant header keys: ['\ufeffid', 'name']
# noncompliant row['id']: None
# compliant header keys:    ['id', 'name']
# compliant row['id']:    1
# len(str)=4  len(bytes)=5  bytes=b'Jos\xc3\xa9'
# decode as latin-1 (never fails): JosÃ©
# decode ascii errors='strict'           UnicodeDecodeError: ordinal not in range(128) at 3
# decode ascii errors='replace'          'Jos��'
# decode ascii errors='ignore'           'Jos'
# decode ascii errors='backslashreplace' 'Jos\\xc3\\xa9'
# raw[:4].decode() -> UnicodeDecodeError: unexpected end of data
# noncompliant: cut to 4 bytes -> 'Ærøs'     6 bytes, fits: False
# compliant:    cut to 4 bytes -> 'Ær'       3 bytes, fits: True
