"""tracemalloc — where does the memory go, reported in a way that is stable

https://docs.python.org/3/library/tracemalloc.html

The obvious "summarise this log" reads the whole file, splits it into a
list, turns every line into a dict and only then counts. On a 10 KB sample
that is invisible; on a 4 GB log the pod is OOM-killed. The streaming version
holds one line at a time and keeps only the counters.

`tracemalloc` shows both the peak and the source line that allocated it.
Exact byte counts differ between Python versions and platforms, so do not
assert on them: compare the two versions against each other, put sizes into
coarse buckets, and check *which line* is the top allocation site. Those
answers are the same everywhere, and they are what the reviewer needs.
"""

import io
import linecache
import tracemalloc
from collections import Counter

LEVELS = ["INFO", "INFO", "INFO", "WARN", "ERROR"]
DATA = "".join(f"2026-09-30T10:{i // 60 % 60:02d}:{i % 60:02d} {LEVELS[i % 5]} "
               f"req={i:06d} path=/api/v1/orders/{i % 977} status=200\n" for i in range(40_000))


def load_records(stream: io.StringIO) -> list[dict]:
    lines = stream.read().splitlines()
    return [dict(zip(("ts", "level", "req", "path", "status"), line.split())) for line in lines]


def noncompliant(stream: io.StringIO) -> Counter:
    records = load_records(stream)
    return Counter(record["level"] for record in records)


def compliant(stream: io.StringIO) -> Counter:
    counts: Counter = Counter()
    for line in stream:  # one line in memory at a time
        counts[line.split(" ", 2)[1]] += 1
    return counts


def bucket(size: int) -> str:
    for limit, label in ((64 * 1024, "< 64 KiB"), (1024 ** 2, "< 1 MiB"), (16 * 1024 ** 2, "< 16 MiB")):
        if size < limit:
            return label
    return ">= 16 MiB"


def peak_of(fn) -> tuple[Counter, int]:
    stream = io.StringIO(DATA)  # the input itself is not charged to fn
    tracemalloc.start()
    try:
        result = fn(stream)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, peak


def top_sites(fn) -> list[tuple[str, str]]:
    """Lines of this file whose allocations are still alive after fn returns."""
    stream = io.StringIO(DATA)
    tracemalloc.start()
    try:
        before = tracemalloc.take_snapshot()
        kept = fn(stream)  # noqa: F841 - keep the result alive for the snapshot
        after = tracemalloc.take_snapshot()
    finally:
        tracemalloc.stop()
    here = tracemalloc.Filter(True, __file__)
    diff = after.filter_traces([here]).compare_to(before.filter_traces([here]), "lineno")
    sites = []
    for stat in diff:
        if stat.size_diff >= 64 * 1024:
            frame = stat.traceback[0]
            sites.append((linecache.getline(frame.filename, frame.lineno).strip(),
                          bucket(stat.size_diff)))
    return sites


def main() -> None:
    peaks = {}
    for fn in (noncompliant, compliant):
        counts, peak = peak_of(fn)
        peaks[fn.__name__] = peak
        print(f"{fn.__name__ + ':':<14}counts={dict(sorted(counts.items()))} peak {bucket(peak)}")
    ratio = peaks["noncompliant"] / peaks["compliant"]
    print(f"peak ratio noncompliant/compliant: {'more than 100x' if ratio > 100 else 'under 100x'}")
    print()
    for fn in (load_records, compliant):
        sites = top_sites(fn)
        print(f"{fn.__name__}: {len(sites)} allocation site(s) >= 64 KiB still alive afterwards")
        for source, size in sites:
            print(f"  {size:<9} {source}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: counts={'ERROR': 8000, 'INFO': 24000, 'WARN': 8000} peak >= 16 MiB
# compliant:    counts={'ERROR': 8000, 'INFO': 24000, 'WARN': 8000} peak < 64 KiB
# peak ratio noncompliant/compliant: more than 100x
#
# load_records: 1 allocation site(s) >= 64 KiB still alive afterwards
#   >= 16 MiB return [dict(zip(("ts", "level", "req", "path", "status"), line.split())) for line in lines]
# compliant: 0 allocation site(s) >= 64 KiB still alive afterwards
