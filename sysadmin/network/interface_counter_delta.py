"""Interface counters v2: Counter32 vs Counter64 deltas, bps and utilization

ifInOctets/ifOutOctets are Counter32: they count up to 2**32 - 1 and then
silently start again at 0. If the new value is smaller, assume exactly one
wrap and add the modulus. A smaller value can also mean the device rebooted;
if sysUpTime went backwards the sample is a discontinuity and is dropped.

"Exactly one wrap" is the catch. 2**32 octets is 34.4 Gbit, so a 10G link at
line rate wraps a Counter32 every 3.4 seconds. Polled every 5 minutes, the
32-bit delta of a busy 10G port is a random number, and no arithmetic can
recover it. That is why RFC 2863 added ifXTable: ifHCInOctets/ifHCOutOctets
are Counter64 (wrap after centuries at 100G) and ifHighSpeed gives the speed
in Mbit/s, because ifSpeed (Gauge32, bit/s) tops out at 4.29 Gbit/s.

Rule of thumb printed below: a Counter32 wraps every 2**32 * 8 / speed
seconds at line rate. With 5-minute polls, any port that can average more
than ~114 Mbit/s over the interval needs the HC counters; port 2 below is
just under that line, which is exactly how this bug hides in testing.
"""

from dataclasses import dataclass

COUNTER32 = 2**32
COUNTER64 = 2**64


@dataclass(frozen=True)
class Poll:
    uptime_ticks: int  # sysUpTime, hundredths of a second
    counters: dict[str, int]  # "ifHCInOctets.3" -> value


def counter_delta(old: int, new: int, modulus: int) -> int:
    if new >= old:
        return new - old
    return new + modulus - old


def interval_deltas(before: Poll, after: Poll) -> tuple[float, dict[str, int]] | None:
    if after.uptime_ticks < before.uptime_ticks:
        return None  # discontinuity: agent or device restarted
    seconds = (after.uptime_ticks - before.uptime_ticks) / 100
    out = {}
    for key, value in after.counters.items():
        if key not in before.counters:
            continue
        modulus = COUNTER64 if key.startswith("ifHC") else COUNTER32
        out[key] = counter_delta(before.counters[key], value, modulus)
    return seconds, out


def human_bps(bps: float) -> str:
    for unit, scale in (("Gbit/s", 1e9), ("Mbit/s", 1e6), ("kbit/s", 1e3)):
        if bps >= scale:
            return f"{bps / scale:.2f} {unit}"
    return f"{bps:.0f} bit/s"


# ifHighSpeed (Mbit/s) per ifIndex
HIGH_SPEED = {1: 10_000, 2: 1_000, 3: 100}

# Two polls 300 s apart. The device keeps ifInOctets as the low 32 bits of the
# 64-bit counter, which is what most agents do.
_HC_BEFORE = {1: 81_604_378_607, 2: 9_877_120_331, 3: 1_550_208_114}
_HC_AFTER = {1: 81_604_378_607 + 221_377_946_250, 2: 9_877_120_331 + 4_110_532_800,
             3: 1_550_208_114 + 412_877_500}
BEFORE = Poll(81_234_500, {**{f"ifHCInOctets.{i}": v for i, v in _HC_BEFORE.items()},
                           **{f"ifInOctets.{i}": v % COUNTER32 for i, v in _HC_BEFORE.items()}})
AFTER = Poll(81_264_500, {**{f"ifHCInOctets.{i}": v for i, v in _HC_AFTER.items()},
                          **{f"ifInOctets.{i}": v % COUNTER32 for i, v in _HC_AFTER.items()}})


def main() -> None:
    result = interval_deltas(BEFORE, AFTER)
    assert result is not None
    seconds, deltas = result
    print(f"interval: {seconds:.0f} s")
    print(f"{'if':>2} {'speed':>8}  {'Counter32 says':>15}  {'Counter64 says':>15}  util  "
          "32-bit wrap at line rate")
    for index, mbps in HIGH_SPEED.items():
        bps32 = deltas[f"ifInOctets.{index}"] * 8 / seconds
        bps64 = deltas[f"ifHCInOctets.{index}"] * 8 / seconds
        util = bps64 / (mbps * 1_000_000) * 100
        wrap = COUNTER32 * 8 / (mbps * 1_000_000)
        print(f"{index:>2} {mbps:>5} Mb  {human_bps(bps32):>15}  {human_bps(bps64):>15}  "
              f"{util:>3.0f}%  {wrap:>12.1f} s")

    print()
    print("Counter64 wrap is handled the same way (agents that start near 2**64):")
    print("  delta =", counter_delta(COUNTER64 - 1_000, 5_000, COUNTER64))

    reboot = Poll(4_100, {k: 0 for k in AFTER.counters})
    print("after a reload:", interval_deltas(AFTER, reboot))


if __name__ == "__main__":
    main()

# Output:
# interval: 300 s
# if    speed   Counter32 says   Counter64 says  util  32-bit wrap at line rate
#  1 10000 Mb     62.26 Mbit/s      5.90 Gbit/s   59%           3.4 s
#  2  1000 Mb    109.61 Mbit/s    109.61 Mbit/s   11%          34.4 s
#  3   100 Mb     11.01 Mbit/s     11.01 Mbit/s   11%         343.6 s
#
# Counter64 wrap is handled the same way (agents that start near 2**64):
#   delta = 6000
# after a reload: None
