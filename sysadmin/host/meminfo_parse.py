"""Parsing /proc/meminfo — use MemAvailable, not MemFree

https://www.kernel.org/doc/html/latest/filesystems/proc.html#meminfo

"Free memory is 3%, the box is about to die" is the classic false alarm.
Linux uses idle RAM as page cache, so MemFree is always low on a healthy
server. Since kernel 3.14 the kernel publishes MemAvailable: its own estimate
of how much can be handed to new processes without swapping. Alert on that,
and on swap actually in use, not on MemFree.

/proc/meminfo is "Key:   value kB" lines, a few of them without a unit
(HugePages_Total is a page count). Parse it into a dict of ints, keep the
unit handling explicit, and fall back to the old Free+Buffers+Cached formula
only for ancient kernels that lack MemAvailable. The sample is embedded so
the output is the same everywhere; on Linux pass open("/proc/meminfo").read().
"""

MEMINFO_SAMPLE = """\
MemTotal:       16303428 kB
MemFree:          498212 kB
MemAvailable:    9874420 kB
Buffers:          402128 kB
Cached:          8712340 kB
SwapCached:        12036 kB
Active:          7120564 kB
Inactive:        6215408 kB
Shmem:            321448 kB
Slab:             912556 kB
SReclaimable:     688120 kB
SwapTotal:       4194300 kB
SwapFree:        3989500 kB
Dirty:              1284 kB
HugePages_Total:       0
HugePages_Free:        0
Hugepagesize:       2048 kB
"""

# The same host from a kernel older than 3.14: no MemAvailable line.
OLD_KERNEL_SAMPLE = """\
MemTotal:        4046352 kB
MemFree:          101220 kB
Buffers:           20512 kB
Cached:           310448 kB
SwapTotal:       2097148 kB
SwapFree:         184320 kB
"""


def parse_meminfo(text: str) -> dict[str, int]:
    """Return values in bytes for kB fields and as plain counts otherwise."""
    info = {}
    for line in text.splitlines():
        key, sep, rest = line.partition(":")
        if not sep:
            continue
        fields = rest.split()
        value = int(fields[0])
        if len(fields) > 1:
            if fields[1] != "kB":
                raise ValueError(f"unexpected unit {fields[1]!r} for {key}")
            value *= 1024
        info[key.strip()] = value
    return info


def available(info: dict[str, int]) -> tuple[int, str]:
    if "MemAvailable" in info:
        return info["MemAvailable"], "MemAvailable"
    # Pre-3.14 approximation: overestimates, because not all cache is reclaimable.
    return info["MemFree"] + info.get("Buffers", 0) + info.get("Cached", 0), "estimate"


def gib(n: int) -> str:
    return f"{n / 1024**3:.2f} GiB"


def report(name: str, text: str, min_avail_pct: float = 15.0, max_swap_pct: float = 50.0) -> None:
    info = parse_meminfo(text)
    total = info["MemTotal"]
    avail, source = available(info)
    avail_pct = avail / total * 100
    free_pct = info["MemFree"] / total * 100
    swap_used = info["SwapTotal"] - info["SwapFree"]
    swap_pct = swap_used / info["SwapTotal"] * 100 if info["SwapTotal"] else 0.0

    print(f"[{name}]")
    print(f"  total      {gib(total)}")
    print(f"  free       {gib(info['MemFree'])} ({free_pct:.1f}%)  <- looks scary, means little")
    print(f"  available  {gib(avail)} ({avail_pct:.1f}%, from {source})")
    print(f"  swap used  {gib(swap_used)} ({swap_pct:.1f}%)")
    alerts = []
    if avail_pct < min_avail_pct:
        alerts.append(f"available below {min_avail_pct:.0f}%")
    if swap_pct > max_swap_pct:
        alerts.append(f"swap above {max_swap_pct:.0f}%")
    print("  status    ", "ALERT: " + "; ".join(alerts) if alerts else "OK")


def main() -> None:
    report("app-03, kernel 6.8", MEMINFO_SAMPLE)
    report("legacy-01, kernel 3.10", OLD_KERNEL_SAMPLE)
    info = parse_meminfo(MEMINFO_SAMPLE)
    print("hugepages configured:", info["HugePages_Total"], "(a count, not kB)")
    try:
        parse_meminfo("Weird:  12 MB\n")
    except ValueError as exc:
        print("rejected:", exc)


if __name__ == "__main__":
    main()

# Output:
# [app-03, kernel 6.8]
#   total      15.55 GiB
#   free       0.48 GiB (3.1%)  <- looks scary, means little
#   available  9.42 GiB (60.6%, from MemAvailable)
#   swap used  0.20 GiB (4.9%)
#   status     OK
# [legacy-01, kernel 3.10]
#   total      3.86 GiB
#   free       0.10 GiB (2.5%)  <- looks scary, means little
#   available  0.41 GiB (10.7%, from estimate)
#   swap used  1.82 GiB (91.2%)
#   status     ALERT: available below 15%; swap above 50%
# hugepages configured: 0 (a count, not kB)
# rejected: unexpected unit 'MB' for Weird
