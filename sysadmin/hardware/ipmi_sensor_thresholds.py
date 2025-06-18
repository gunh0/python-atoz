"""IPMI: parse `ipmitool sensor` and check readings against BMC thresholds

`ipmitool sensor` prints one pipe-separated row per sensor: name, reading,
unit, status, then six thresholds in a fixed order -- lower non-recoverable,
lower critical, lower non-critical, upper non-critical, upper critical,
upper non-recoverable (lnr lcr lnc unc ucr unr). Missing values are "na",
and discrete sensors (PSU presence, intrusion) put a hex state like "0x01"
in the reading column, so the parser must not assume every row is numeric.
For power supplies the bits are defined by the IPMI spec (sensor type 0x08):
bit 0 presence, bit 1 failure, bit 3 input lost, and so on.

The status column is what the BMC thinks. It is worth recomputing it from
the thresholds yourself: some BMCs report "ok" for a sensor that has no
reading at all ("na"), and the distance to the nearest threshold (headroom)
is far more useful on a dashboard than a binary ok/cr.
"""

from dataclasses import dataclass

SENSOR = """\
CPU1 Temp        | 61.000     | degrees C  | ok    | 0.000     | 0.000     | 0.000     | 87.000    | 92.000    | 92.000
CPU2 Temp        | 89.000     | degrees C  | nc    | 0.000     | 0.000     | 0.000     | 87.000    | 92.000    | 92.000
Inlet Temp       | 24.000     | degrees C  | ok    | -7.000    | -5.000    | 0.000     | 40.000    | 42.000    | 47.000
Exhaust Temp     | na         | degrees C  | na    | na        | na        | na        | 70.000    | 75.000    | 80.000
FAN1             | 5640.000   | RPM        | ok    | 300.000   | 500.000   | 700.000   | na        | na        | na
FAN2             | 5520.000   | RPM        | ok    | 300.000   | 500.000   | 700.000   | na        | na        | na
FAN3             | 420.000    | RPM        | cr    | 300.000   | 500.000   | 700.000   | na        | na        | na
FAN4             | 5580.000   | RPM        | ok    | 300.000   | 500.000   | 700.000   | na        | na        | na
PSU1 Status      | 0x01       | discrete   | 0x0100| na        | na        | na        | na        | na        | na
PSU2 Status      | 0x09       | discrete   | 0x0900| na        | na        | na        | na        | na        | na
12V              | 12.063     | Volts      | ok    | 10.173    | 10.692    | na        | na        | 13.296    | 13.815
"""

THRESHOLDS = ("lnr", "lcr", "lnc", "unc", "ucr", "unr")
# Checked from most to least severe so the first hit wins.
RULES = (
    ("unr", ">=", "non-recoverable"), ("lnr", "<=", "non-recoverable"),
    ("ucr", ">=", "critical"), ("lcr", "<=", "critical"),
    ("unc", ">=", "warning"), ("lnc", "<=", "warning"),
)


# IPMI sensor type 0x08 (Power Supply) discrete offsets, bit -> meaning.
PSU_STATE_BITS = {0: "presence", 1: "failure", 2: "predictive failure", 3: "input lost",
                  4: "input out of range", 6: "config error"}


def decode_psu(raw: str) -> str:
    bits = int(raw, 16)
    names = [name for bit, name in PSU_STATE_BITS.items() if bits & (1 << bit)]
    return ", ".join(names) or "absent"


def number(text: str) -> float | None:
    try:
        return float(text)
    except ValueError:
        return None  # "na", or a discrete "0x01"


@dataclass
class Sensor:
    name: str
    raw: str
    unit: str
    bmc_status: str
    limits: dict[str, float]

    @property
    def value(self) -> float | None:
        return None if self.unit == "discrete" else number(self.raw)


def parse_sensor(text: str) -> list[Sensor]:
    sensors = []
    for line in text.splitlines():
        cols = [c.strip() for c in line.split("|")]
        if len(cols) != 10:
            continue
        name, raw, unit, status, *rest = cols
        limits = {k: v for k, v in zip(THRESHOLDS, map(number, rest)) if v is not None}
        sensors.append(Sensor(name, raw, unit, status, limits))
    return sensors


def evaluate(sensor: Sensor) -> tuple[str, str]:
    """Return (our status, headroom text)."""
    value = sensor.value
    if sensor.unit == "discrete":
        if sensor.name.startswith("PSU"):
            state = decode_psu(sensor.raw)
            return ("ok" if state == "presence" else "critical"), state
        return "discrete", ""
    if value is None:
        return "NO READING", ""
    for key, op, level in RULES:
        limit = sensor.limits.get(key)
        # A threshold of 0 on a temperature is "not configured" on many boards.
        if limit is None or (limit == 0 and key.startswith("l") and sensor.unit == "degrees C"):
            continue
        if (op == ">=" and value >= limit) or (op == "<=" and value <= limit):
            return level, f"past {key} {limit:g}"
    upper = [sensor.limits[k] - value for k in ("unc", "ucr") if k in sensor.limits]
    lower = [value - sensor.limits[k] for k in ("lnc", "lcr") if k in sensor.limits]
    room = min(upper + lower, default=None)
    return "ok", "" if room is None else f"{round(room, 3):g} {sensor.unit.split()[-1]} to next threshold"


def main() -> None:
    for s in parse_sensor(SENSOR):
        ours, detail = evaluate(s)
        shown = s.raw if s.value is None else f"{s.value:g}"
        flag = "" if ours in ("ok", "discrete") else "  <--"
        # BMC says ok/na while we disagree: exactly the case a status-only check misses
        if s.bmc_status in ("ok", "na") and flag:
            flag += " (bmc did not flag this)"
        print(f"{s.name:<13} {shown:>6} {s.unit:<10} bmc={s.bmc_status:<6} ours={ours:<15} "
              f"{detail}{flag}".rstrip())


if __name__ == "__main__":
    main()

# Output:
# CPU1 Temp         61 degrees C  bmc=ok     ours=ok              26 C to next threshold
# CPU2 Temp         89 degrees C  bmc=nc     ours=warning         past unc 87  <--
# Inlet Temp        24 degrees C  bmc=ok     ours=ok              16 C to next threshold
# Exhaust Temp      na degrees C  bmc=na     ours=NO READING        <-- (bmc did not flag this)
# FAN1            5640 RPM        bmc=ok     ours=ok              4940 RPM to next threshold
# FAN2            5520 RPM        bmc=ok     ours=ok              4820 RPM to next threshold
# FAN3             420 RPM        bmc=cr     ours=critical        past lcr 500  <--
# FAN4            5580 RPM        bmc=ok     ours=ok              4880 RPM to next threshold
# PSU1 Status     0x01 discrete   bmc=0x0100 ours=ok              presence
# PSU2 Status     0x09 discrete   bmc=0x0900 ours=critical        presence, input lost  <--
# 12V           12.063 Volts      bmc=ok     ours=ok              1.233 Volts to next threshold
