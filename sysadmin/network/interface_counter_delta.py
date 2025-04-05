"""Interface counters: delta between two SNMP polls, with Counter32 wrap

ifInOctets/ifOutOctets are Counter32: they count up to 2**32 - 1 and then
silently start again at 0. Subtracting old from new gives a huge negative
number once per wrap, and a graph that "dips below zero" or a monitoring rule
that ignores negatives both hide real traffic. If the new value is smaller,
assume exactly one wrap and add 2**32.

A smaller value can also mean the device rebooted (or the line card was
reseated) and the counter restarted from zero. RFC 2863 calls that a
discontinuity; the cheap check is sysUpTime: if it went backwards, the delta
is meaningless and the sample must be dropped, not "corrected". (sysUpTime
is itself 32-bit TimeTicks and wraps after ~497 days; this version ignores
that rare case.)
"""

from dataclasses import dataclass

COUNTER32 = 2**32


@dataclass(frozen=True)
class Poll:
    uptime_ticks: int  # sysUpTime, hundredths of a second
    counters: dict[str, int]  # "ifInOctets.1" -> value


def counter_delta(old: int, new: int, modulus: int = COUNTER32) -> int:
    if new >= old:
        return new - old
    return new + modulus - old


def deltas(before: Poll, after: Poll) -> dict[str, int | None]:
    if after.uptime_ticks < before.uptime_ticks:
        return {key: None for key in after.counters}  # agent restarted
    return {
        key: counter_delta(before.counters[key], value)
        for key, value in after.counters.items()
        if key in before.counters
    }


# Three polls of edge-sw02, five minutes apart (30000 ticks).
POLLS = [
    Poll(81_234_500, {"ifInOctets.1": 4_291_000_000, "ifOutOctets.1": 1_200_000_000,
                      "ifInOctets.2": 88_000, "ifOutOctets.2": 91_500}),
    Poll(81_264_500, {"ifInOctets.1": 210_032_704, "ifOutOctets.1": 1_390_000_000,
                      "ifInOctets.2": 88_000, "ifOutOctets.2": 91_500}),
    # the switch reloaded between these two polls
    Poll(4_100, {"ifInOctets.1": 5_120_000, "ifOutOctets.1": 2_400_000,
                 "ifInOctets.2": 0, "ifOutOctets.2": 0}),
]


def main() -> None:
    for n, (before, after) in enumerate(zip(POLLS, POLLS[1:]), start=1):
        seconds = (after.uptime_ticks - before.uptime_ticks) / 100
        print(f"interval {n}: {seconds:+.0f} s of sysUpTime")
        for key, delta in deltas(before, after).items():
            naive = after.counters[key] - before.counters[key]
            shown = "discarded (discontinuity)" if delta is None else f"{delta:>13,}"
            print(f"  {key:<14} naive {naive:>15,}  delta {shown}")


if __name__ == "__main__":
    main()

# Output:
# interval 1: +300 s of sysUpTime
#   ifInOctets.1   naive  -4,080,967,296  delta   214,000,000
#   ifOutOctets.1  naive     190,000,000  delta   190,000,000
#   ifInOctets.2   naive               0  delta             0
#   ifOutOctets.2  naive               0  delta             0
# interval 2: -812604 s of sysUpTime
#   ifInOctets.1   naive    -204,912,704  delta discarded (discontinuity)
#   ifOutOctets.1  naive  -1,387,600,000  delta discarded (discontinuity)
#   ifInOctets.2   naive         -88,000  delta discarded (discontinuity)
#   ifOutOctets.2  naive         -91,500  delta discarded (discontinuity)
