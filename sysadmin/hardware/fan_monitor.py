"""Fan monitor v1: `ipmitool sdr type Fan` across hosts with our own RPM policy

`ipmitool sdr type Fan` is cheap enough to run every minute on every host:
name | sensor id | status | entity | reading. The BMC's own thresholds are
often useless for alerting -- a lower critical of 300-500 RPM means the fan
has effectively stopped before anything fires. So this monitor ignores the
BMC status column for numeric readings and applies a site policy instead:
warning below 2500 RPM, critical below 1500 RPM.

Non-numeric readings are their own class. "No Reading" with status "ns" is
a missing or unplugged fan (or a BMC that lost the sensor) and is UNKNOWN,
not OK. The discrete "Fan Redundancy" sensor is checked by its text -- and
note app07 below: two fans without readings while redundancy still claims
"Fully Redundant". Never trust one sensor to vouch for the others.
"""

from dataclasses import dataclass

SDR_FAN = {
    "db01": """\
FAN1             | 30h | ok  | 29.1 | 5640 RPM
FAN2             | 31h | ok  | 29.2 | 5520 RPM
FAN3             | 32h | cr  | 29.3 | 420 RPM
FAN4             | 33h | ok  | 29.4 | 5580 RPM
Fan Redundancy   | 74h | ok  |  7.1 | Redundancy Lost
""",
    "db02": """\
FAN1             | 30h | ok  | 29.1 | 5460 RPM
FAN2             | 31h | ok  | 29.2 | 2280 RPM
FAN3             | 32h | ok  | 29.3 | 5400 RPM
FAN4             | 33h | ok  | 29.4 | 5520 RPM
Fan Redundancy   | 74h | ok  |  7.1 | Fully Redundant
""",
    "app07": """\
FAN1A            | 30h | ok  | 29.1 | 8040 RPM
FAN1B            | 31h | ok  | 29.1 | 7920 RPM
FAN2A            | 32h | ns  | 29.2 | No Reading
FAN2B            | 33h | ns  | 29.2 | No Reading
Fan Redundancy   | 74h | ok  |  7.1 | Fully Redundant
""",
}

WARN_RPM = 2500
CRIT_RPM = 1500
# Nagios exit codes put UNKNOWN (3) above CRITICAL (2); for "which is worst"
# a dead fan still outranks a missing reading, so rank and exit code differ.
EXIT_CODE = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}
RANK = {"OK": 0, "UNKNOWN": 1, "WARNING": 2, "CRITICAL": 3}


@dataclass
class FanReading:
    host: str
    name: str
    bmc_status: str
    reading: str

    @property
    def rpm(self) -> int | None:
        value, _, unit = self.reading.partition(" ")
        return int(float(value)) if unit == "RPM" else None


def parse_sdr(host: str, text: str) -> list[FanReading]:
    out = []
    for line in text.splitlines():
        cols = [c.strip() for c in line.split("|")]
        if len(cols) == 5:
            out.append(FanReading(host, cols[0], cols[2], cols[4]))
    return out


def check(fan: FanReading) -> tuple[str, str]:
    if fan.name == "Fan Redundancy":
        return ("OK", fan.reading) if fan.reading == "Fully Redundant" else ("WARNING", fan.reading)
    rpm = fan.rpm
    if rpm is None:
        return "UNKNOWN", f"{fan.reading} (bmc status {fan.bmc_status})"
    if rpm < CRIT_RPM:
        return "CRITICAL", f"{rpm} RPM < {CRIT_RPM}"
    if rpm < WARN_RPM:
        return "WARNING", f"{rpm} RPM < {WARN_RPM} (bmc says {fan.bmc_status})"
    return "OK", f"{rpm} RPM"


def main() -> None:
    worst = "OK"
    for host, text in SDR_FAN.items():
        results = [(fan, *check(fan)) for fan in parse_sdr(host, text)]
        host_worst = max((state for _, state, _ in results), key=RANK.__getitem__)
        print(f"{host}: {host_worst}")
        for fan, state, detail in results:
            if state != "OK":
                print(f"  {state:<8} {fan.name:<15} {detail}")
        worst = max(worst, host_worst, key=RANK.__getitem__)
    print(f"overall: {worst} (exit {EXIT_CODE[worst]})")


if __name__ == "__main__":
    main()

# Output:
# db01: CRITICAL
#   CRITICAL FAN3            420 RPM < 1500
#   WARNING  Fan Redundancy  Redundancy Lost
# db02: WARNING
#   WARNING  FAN2            2280 RPM < 2500 (bmc says ok)
# app07: UNKNOWN
#   UNKNOWN  FAN2A           No Reading (bmc status ns)
#   UNKNOWN  FAN2B           No Reading (bmc status ns)
# overall: CRITICAL (exit 2)
