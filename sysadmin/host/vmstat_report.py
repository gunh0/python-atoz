"""vmstat report v1 — turn `vmstat -t` samples into a CSV for the capacity review

The monthly capacity meeting does not read terminal output; it wants a
sheet. v1 converts `vmstat -t 5` output (the -t flag appends a timestamp to
every line) into CSV with the csv module, which handles quoting and the
line terminator so you never hand-join strings with commas. Columns are
renamed to what a reader understands, memory is converted from KiB to MiB,
and a derived "cpu_busy" (100 - idle) column is added, because that is the
one number people chart. The boot-average first line is dropped.

The file goes to a temporary directory and is read back with DictReader,
which is how you should test an exporter: by parsing what it wrote.
"""

import csv
import io
import tempfile
from pathlib import Path

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


def main() -> None:
    records = [to_record(v) for v in parse(VMSTAT_T_SAMPLE)]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "vmstat-web-01.csv"
        write_csv(records, path)
        raw = path.read_bytes()
        back = list(csv.DictReader(io.StringIO(raw.decode("utf-8"), newline="")))

    ending = raw.splitlines(keepends=True)[0][-2:]
    print(f"wrote {len(records)} rows, {len(raw)} bytes, line ending {ending!r}")
    print(raw.decode("utf-8").replace("\r\n", "\n"), end="")
    peak = max(back, key=lambda r: int(r["cpu_busy"]))
    print(f"peak cpu_busy {peak['cpu_busy']}% at {peak['time']} (run queue {peak['run_queue']})")
    print("round trip intact:", [r["time"] for r in back] == [r["time"] for r in records])


if __name__ == "__main__":
    main()

# Output:
# wrote 5 rows, 387 bytes, line ending b'\r\n'
# time,run_queue,blocked,free_mib,cache_mib,swap_in,swap_out,cpu_user,cpu_system,cpu_iowait,cpu_busy
# 2026-03-14 10:00:05 UTC,3,0,1759.1,8917.2,0,0,31,6,2,39
# 2026-03-14 10:00:10 UTC,6,1,1681.6,8935.7,0,0,58,11,4,73
# 2026-03-14 10:00:15 UTC,7,2,1650.5,8946.3,0,0,64,12,9,85
# 2026-03-14 10:00:20 UTC,4,0,1713.3,8943.6,0,0,40,8,2,50
# 2026-03-14 10:00:25 UTC,2,0,1755.9,8944.3,0,0,22,5,1,28
# peak cpu_busy 85% at 2026-03-14 10:00:15 UTC (run queue 7)
# round trip intact: True
