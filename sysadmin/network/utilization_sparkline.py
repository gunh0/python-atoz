"""Link utilization in the terminal: sparklines and a bar graph from counters

When you are on a jump host with only SSH, a one-line sparkline per port
answers "when is this uplink busy?" faster than opening the NMS. The input is
what an SNMP poller stores: ifHCInOctets per sample. Utilization is
delta * 8 / seconds / speed.

The trap is autoscaling. Scaling each sparkline to its own min/max makes a
port idling at 0.2-0.5% look exactly as alarming as one at 40-95%. For
utilization the scale is fixed: 0-100% of the link speed. Two glyph sets are
shown: Unicode blocks, and a plain-ASCII ramp for terminals and log files
that mangle UTF-8.
"""

BLOCKS = "▁▂▃▄▅▆▇█"
ASCII_RAMP = " .:-=+*#"

SPEED_BPS = {"Te1/1/1 (uplink)": 10_000_000_000, "Gi1/0/48 (backup)": 1_000_000_000}
INTERVAL = 3600  # hourly samples, 00:00..24:00

# Hourly average traffic (Mbit/s) the poller saw; turned into octet counters
# below so the example starts from the same data a real poller stores.
MBPS = {
    "Te1/1/1 (uplink)": [410, 380, 350, 330, 320, 360, 700, 1900, 4200, 5600, 6100, 6400,
                         5900, 6300, 6800, 7200, 8100, 8900, 9400, 9100, 7600, 4800, 2100, 900],
    "Gi1/0/48 (backup)": [2, 2, 3, 5, 4, 3, 2, 2, 2, 3, 2, 2,
                          2, 3, 2, 2, 2, 3, 2, 2, 3, 2, 2, 2],
}


def counters_from_rates(mbps: list[int], start: int = 7_340_118_002_112) -> list[int]:
    values = [start]
    for rate in mbps:
        values.append(values[-1] + rate * 1_000_000 * INTERVAL // 8)
    return values


def utilization(counters: list[int], speed_bps: int) -> list[float]:
    return [(b - a) * 8 / INTERVAL / speed_bps * 100 for a, b in zip(counters, counters[1:])]


def sparkline(values: list[float], glyphs: str, low: float, high: float) -> str:
    span = (high - low) or 1.0
    top = len(glyphs) - 1
    return "".join(glyphs[min(top, max(0, round((v - low) / span * top)))] for v in values)


def bar_graph(values: list[float], width: int = 50, mark: float = 80.0) -> list[str]:
    rows = []
    mark_col = round(mark / 100 * width)
    for hour, value in enumerate(values):
        cells = ["#" if i < round(value / 100 * width) else " " for i in range(width)]
        if cells[mark_col - 1] == " ":
            cells[mark_col - 1] = "|"
        flag = " over" if value >= mark else ""
        rows.append(f"{hour:02d}:00 {''.join(cells)} {value:5.1f}%{flag}")
    return rows


def main() -> None:
    series = {name: utilization(counters_from_rates(MBPS[name]), speed)
              for name, speed in SPEED_BPS.items()}

    print("fixed 0-100% scale:")
    for name, values in series.items():
        print(f"  {name:<18} {sparkline(values, BLOCKS, 0, 100)}  peak {max(values):.1f}%")
    print("autoscaled (misleading):")
    for name, values in series.items():
        print(f"  {name:<18} {sparkline(values, BLOCKS, min(values), max(values))}")
    print("ascii ramp, fixed scale:")
    for name, values in series.items():
        print(f"  {name:<18} [{sparkline(values, ASCII_RAMP, 0, 100)}]")

    print()
    print("Te1/1/1 hourly, '|' = 80%:")
    for row in bar_graph(series["Te1/1/1 (uplink)"])[14:21]:
        print(" ", row)


if __name__ == "__main__":
    main()

# Output:
# fixed 0-100% scale:
#   Te1/1/1 (uplink)   ▁▁▁▁▁▁▁▂▄▅▅▅▅▅▆▆▇▇█▇▆▄▂▂  peak 94.0%
#   Gi1/0/48 (backup)  ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁  peak 0.5%
# autoscaled (misleading):
#   Te1/1/1 (uplink)   ▁▁▁▁▁▁▁▂▄▅▅▆▅▆▆▆▇███▇▄▂▁
#   Gi1/0/48 (backup)  ▁▁▃█▆▃▁▁▁▃▁▁▁▃▁▁▁▃▁▁▃▁▁▁
# ascii ramp, fixed scale:
#   Te1/1/1 (uplink)   [       .-=====++**#*+-..]
#   Gi1/0/48 (backup)  [                        ]
#
# Te1/1/1 hourly, '|' = 80%:
#   14:00 ##################################     |            68.0%
#   15:00 ####################################   |            72.0%
#   16:00 ########################################            81.0% over
#   17:00 ############################################        89.0% over
#   18:00 ###############################################     94.0% over
#   19:00 ##############################################      91.0% over
#   20:00 ###################################### |            76.0%
