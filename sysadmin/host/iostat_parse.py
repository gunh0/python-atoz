"""Parsing `iostat -dx 1 2` — which disk is the bottleneck, and when %util lies

iostat -x is where "the database is slow" turns into a device name. Like
vmstat, the first report covers the time since boot, so `iostat -dx 1 2`
is read from its second report (or use -y to suppress the first). The
column set differs between sysstat versions (await/svctm in 10.x, r_await,
w_await, aqu-sz and discard columns in 12.x), so the parser maps columns by
the "Device" header of each report rather than by position.

The verdict combines two numbers. %util is the share of time the device had
at least one request in flight; for a single spinning disk 100% means
saturated. For NVMe and RAID volumes, which serve many requests in parallel,
100% only means "busy", so latency (r_await/w_await, in ms) and queue size
(aqu-sz) decide whether users actually wait.
"""

IOSTAT_SAMPLE = """\
Linux 6.8.0-45-generic (db-01) \t03/14/2026 \t_x86_64_\t(32 CPU)

Device            r/s     rkB/s   rrqm/s  %rrqm r_await rareq-sz     w/s     wkB/s   wrqm/s  %wrqm w_await wareq-sz  aqu-sz  %util
dm-0            20.11    810.40     0.00   0.00    1.10    40.30   60.02   1402.11     0.00   0.00    2.31    23.36    0.16   4.10
nvme0n1         14.20    640.88     0.02   0.14    0.18    45.13   58.40   1380.07     1.70   2.83    0.41    23.63    0.03   2.95
sda              3.01    120.50     0.10   3.21    4.80    40.03    2.20     88.04     0.40  15.38    6.12    40.02    0.03   1.40
sdb              0.80     51.20     0.00   0.00    9.70    64.00    1.10     70.40     0.10   8.33   12.40    64.00    0.02   0.90


Device            r/s     rkB/s   rrqm/s  %rrqm r_await rareq-sz     w/s     wkB/s   wrqm/s  %wrqm w_await wareq-sz  aqu-sz  %util
dm-0          1840.00  73600.00     0.00   0.00    0.92    40.00 2210.00  88400.00     0.00   0.00    1.84    40.00    5.76  99.60
nvme0n1       1838.00  73520.00     0.00   0.00    0.30    40.00 2195.00  88330.00    15.00   0.68    0.52    40.24    1.69  99.20
sda             12.00    480.00     0.00   0.00    5.10    40.00    9.00    360.00     1.00  10.00    7.30    40.00    0.13   9.80
sdb            141.00  18048.00     0.00   0.00   38.40   128.00   96.00  12288.00     4.00   4.00   61.70   128.00   11.34  97.40
"""

PARALLEL = ("nvme", "dm-", "md")  # devices that serve many requests at once


def parse_reports(text: str) -> list[dict[str, dict[str, float]]]:
    """Return one {device: {column: value}} dict per report."""
    reports = []
    header = None
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "Device":
            header = fields[1:]
            reports.append({})
        elif header:  # the "Linux ..." banner line comes before any header
            values = [float(v) for v in fields[1:]]
            reports[-1][fields[0]] = dict(zip(header, values))
    return reports


def assess(device: str, s: dict[str, float]) -> str:
    worst_await = max(s["r_await"], s["w_await"])
    parallel = device.startswith(PARALLEL)
    if s["%util"] >= 80 and worst_await >= 20:
        return f"SATURATED: {worst_await:.0f} ms await, queue {s['aqu-sz']:.1f}"
    if s["%util"] >= 80 and parallel:
        return f"busy but fast ({worst_await:.1f} ms) - %util is not saturation here"
    if s["%util"] >= 80:
        return "WARN: near saturation"
    return "ok"


def main() -> None:
    reports = parse_reports(IOSTAT_SAMPLE)
    print(f"{len(reports)} reports; using report 2 (report 1 is since boot)")
    boot, now = reports[0], reports[1]
    print(f"{'device':<8} {'iops':>6} {'MB/s':>7} {'%util':>6}  verdict")
    for device, s in sorted(now.items()):
        iops = s["r/s"] + s["w/s"]
        mbps = (s["rkB/s"] + s["wkB/s"]) / 1024
        print(f"{device:<8} {iops:>6.0f} {mbps:>7.1f} {s['%util']:>6.1f}  {assess(device, s)}")
    busiest = max(now, key=lambda d: now[d]["w_await"])
    print(f"since boot sdb looked idle: {boot['sdb']['%util']}% util -> why report 1 must be skipped")
    print(f"highest write latency now: {busiest} ({now[busiest]['w_await']} ms)")


if __name__ == "__main__":
    main()

# Output:
# 2 reports; using report 2 (report 1 is since boot)
# device     iops    MB/s  %util  verdict
# dm-0       4050   158.2   99.6  busy but fast (1.8 ms) - %util is not saturation here
# nvme0n1    4033   158.1   99.2  busy but fast (0.5 ms) - %util is not saturation here
# sda          21     0.8    9.8  ok
# sdb         237    29.6   97.4  SATURATED: 62 ms await, queue 11.3
# since boot sdb looked idle: 0.9% util -> why report 1 must be skipped
# highest write latency now: sdb (61.7 ms)
