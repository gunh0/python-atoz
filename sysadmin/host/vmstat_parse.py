"""Parsing `vmstat 1 5` — read columns by header name, drop the boot line

vmstat is the quickest "is this box CPU-, memory- or IO-bound?" answer, and
two mistakes make scripted parsing of it wrong. First, the first data line
is the average since boot, not the current state: with `vmstat 1 5` only
lines 2..5 describe the last four seconds. Second, the column set changes
between procps versions: procps-ng 4 appended `gu` (guest time), so the
`awk '{print $NF}'` that used to read steal time `st` on a VM silently
reports guest time after an OS upgrade. Map values by the names in the
second header line instead.

The verdict uses the classic rules of thumb: run queue `r` above the CPU
count means CPU saturation, any swap-in/out (`si`/`so`) means memory
pressure, and a high `wa` means processes are waiting on disk.
"""

from statistics import mean

# procps-ng 3.3 (e.g. RHEL 8), during a backup job
VMSTAT_OLD = """\
procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 1  0      0 812344  91232 6120044    0    0     5    21   48   61  3  1 95  1  0
 2  3      0 790112  91240 6141180    0    0 48120  1204 2210 3984  9  6 41 44  0
 1  4      0 771020  91240 6160332    0    0 51244   980 2301 4102  8  7 38 47  0
 2  3      0 760884  91248 6170412    0    0 46988  1116 2189 3870  9  6 43 42  0
 1  2      0 752100  91248 6179020    0    0 44012  1032 2077 3711  7  5 50 38  0
"""

# procps-ng 4.0 (e.g. Ubuntu 24.04): extra "gu" column, a 4-CPU VM under load
VMSTAT_NEW = """\
procs -----------memory---------- ---swap-- -----io---- -system-- -------cpu-------
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st gu
 0  0  10240 301220  20112 1402120    1    2    10    15  120  210  5  2 92  1  0  0
 9  0  51200 120332  19880 1290444  210  880    22   940 5120 9921 71 26  0  1  2  0
11  1  98304  98112  19004 1251200  402 1610    40  1820 5402 10230 69 28  0  1  2  0
 8  0 131072  87220  18800 1240012  380 1402    31  1601 5288 10012 72 25  0  1  2  0
10  0 163840  81004  18712 1233000  355 1288    28  1544 5190 9877 70 27  0  1  2  0
"""


def parse_vmstat(text: str) -> list[dict[str, int]]:
    lines = text.splitlines()
    names = lines[1].split()
    rows = []
    for line in lines[2:]:
        values = [int(v) for v in line.split()]
        if len(values) != len(names):
            raise ValueError(f"expected {len(names)} columns, got {len(values)}: {line!r}")
        rows.append(dict(zip(names, values)))
    return rows


def verdict(rows: list[dict[str, int]], cpus: int) -> tuple[dict[str, float], list[str]]:
    current = rows[1:]  # rows[0] is the average since boot
    avg = {key: mean(r[key] for r in current) for key in ("r", "b", "si", "so", "us", "sy", "id", "wa")}
    findings = []
    if avg["r"] > cpus:
        findings.append(f"CPU saturated: run queue {avg['r']:.1f} > {cpus} CPUs")
    if avg["si"] + avg["so"] > 0:
        findings.append(f"swapping: si {avg['si']:.0f} / so {avg['so']:.0f} KiB/s")
    if avg["wa"] >= 20:
        findings.append(f"IO wait {avg['wa']:.0f}%, {avg['b']:.1f} procs blocked on IO")
    return avg, findings or ["no bottleneck in this window"]


def show(name: str, text: str, cpus: int) -> None:
    rows = parse_vmstat(text)
    avg, findings = verdict(rows, cpus)
    print(f"[{name}] columns: {' '.join(rows[0])}")
    boot = rows[0]
    print(f"  since boot: us {boot['us']} sy {boot['sy']} id {boot['id']} wa {boot['wa']}   (ignored)")
    print(f"  last {len(rows) - 1}s:    us {avg['us']:.0f} sy {avg['sy']:.0f} id {avg['id']:.0f} wa {avg['wa']:.0f}")
    for finding in findings:
        print(f"  - {finding}")


def main() -> None:
    show("db-02, procps 3.3", VMSTAT_OLD, cpus=8)
    show("api-07, procps 4.0", VMSTAT_NEW, cpus=4)
    new = parse_vmstat(VMSTAT_NEW)[1]
    print(f"api-07 steal time: $NF says {list(new.values())[-1]}, by name st = {new['st']}")


if __name__ == "__main__":
    main()

# Output:
# [db-02, procps 3.3] columns: r b swpd free buff cache si so bi bo in cs us sy id wa st
#   since boot: us 3 sy 1 id 95 wa 1   (ignored)
#   last 4s:    us 8 sy 6 id 43 wa 43
#   - IO wait 43%, 3.0 procs blocked on IO
# [api-07, procps 4.0] columns: r b swpd free buff cache si so bi bo in cs us sy id wa st gu
#   since boot: us 5 sy 2 id 92 wa 1   (ignored)
#   last 4s:    us 70 sy 26 id 0 wa 1
#   - CPU saturated: run queue 9.5 > 4 CPUs
#   - swapping: si 337 / so 1295 KiB/s
# api-07 steal time: $NF says 0, by name st = 2
