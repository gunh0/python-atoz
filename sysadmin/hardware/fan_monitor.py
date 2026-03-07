"""Fan monitor v2: debounce over polls, recovery messages, peer comparison

v1 judged one snapshot. Run every minute, that pages someone for every
single low reading -- and fan tachometers do glitch, especially while the
BMC ramps fan curves. v2 keeps state per fan across polls:

- a new state must be seen on DEBOUNCE consecutive polls before an alert
  (or a recovery) is emitted, so one-off spikes stay quiet;
- only transitions are printed, which is what an alert channel wants;
- a relative rule: a fan running below 60% of the median of its peers is
  flagged even while still above the absolute limits. A failing bearing
  shows up as "slower than its neighbours" days before it crosses 1500 RPM.

The absolute policy (warning < 2500, critical < 1500, "No Reading" is
UNKNOWN) is unchanged from v1.
"""

from dataclasses import dataclass
from statistics import median

WARN_RPM = 2500
CRIT_RPM = 1500
PEER_RATIO = 0.6
DEBOUNCE = 2
RANK = {"OK": 0, "UNKNOWN": 1, "WARNING": 2, "CRITICAL": 3}


def sdr(*readings: str) -> str:
    """Render one `ipmitool sdr type Fan` output in the BMC's exact format."""
    lines = []
    for n, reading in enumerate(readings, start=1):
        status = "ns" if reading == "No Reading" else "ok"
        lines.append(f"FAN{n:<14}| {0x2f + n:02x}h | {status:<3} | 29.{n} | {reading}")
    return "\n".join(lines) + "\n"


# db02, one poll per minute.
POLLS = [
    ("10:00", sdr("5460 RPM", "5520 RPM", "5400 RPM", "5520 RPM")),
    ("10:01", sdr("5460 RPM", "2280 RPM", "5340 RPM", "5520 RPM")),  # FAN2 tach glitch
    ("10:02", sdr("5400 RPM", "5520 RPM", "3120 RPM", "5460 RPM")),  # FAN3 slowing
    ("10:03", sdr("5460 RPM", "5460 RPM", "3000 RPM", "5520 RPM")),
    ("10:04", sdr("5460 RPM", "5520 RPM", "1260 RPM", "5520 RPM")),
    ("10:05", sdr("5400 RPM", "5520 RPM", "1140 RPM", "5460 RPM")),
    ("10:06", sdr("5460 RPM", "5520 RPM", "No Reading", "5520 RPM")),  # pulled for swap
    ("10:07", sdr("5460 RPM", "5520 RPM", "5280 RPM", "5520 RPM")),
    ("10:08", sdr("5460 RPM", "5460 RPM", "5340 RPM", "5520 RPM")),
]


def parse_sdr(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        cols = [c.strip() for c in line.split("|")]
        if len(cols) == 5:
            out[cols[0]] = cols[4]
    return out


def rpm(reading: str) -> int | None:
    value, _, unit = reading.partition(" ")
    return int(float(value)) if unit == "RPM" else None


def evaluate(fans: dict[str, str]) -> dict[str, tuple[str, str]]:
    speeds = {name: rpm(r) for name, r in fans.items()}
    result = {}
    for name, value in speeds.items():
        if value is None:
            result[name] = ("UNKNOWN", fans[name])
            continue
        peers = [v for n, v in speeds.items() if n != name and v is not None]
        if value < CRIT_RPM:
            result[name] = ("CRITICAL", f"{value} RPM < {CRIT_RPM}")
        elif value < WARN_RPM:
            result[name] = ("WARNING", f"{value} RPM < {WARN_RPM}")
        elif peers and value < PEER_RATIO * median(peers):
            result[name] = ("WARNING", f"{value} RPM, peers median {median(peers):.0f}")
        else:
            result[name] = ("OK", f"{value} RPM")
    return result


@dataclass
class FanState:
    reported: str = "OK"
    candidate: str = "OK"
    streak: int = 0


def step(state: FanState, observed: str) -> bool:
    """Feed one observation; return True when the reported state changes."""
    if observed == state.reported:
        state.candidate, state.streak = observed, 0
        return False
    if observed == state.candidate:
        state.streak += 1
    else:
        state.candidate, state.streak = observed, 1
    if state.streak >= DEBOUNCE:
        state.reported, state.streak = observed, 0
        return True
    return False


def main() -> None:
    states: dict[str, FanState] = {}
    for stamp, text in POLLS:
        for name, (observed, detail) in evaluate(parse_sdr(text)).items():
            state = states.setdefault(name, FanState())
            before = state.reported
            if step(state, observed):
                verb = "RECOVERED" if observed == "OK" else observed
                print(f"{stamp} db02 {name}: {verb:<9} ({before} -> {observed}) {detail}")
            elif observed != state.reported:
                print(f"{stamp}   (held) {name}: {observed} {state.streak}/{DEBOUNCE}, {detail}")
    print("final:", ", ".join(f"{n}={s.reported}" for n, s in states.items()))


if __name__ == "__main__":
    main()

# Output:
# 10:01   (held) FAN2: WARNING 1/2, 2280 RPM < 2500
# 10:02   (held) FAN3: WARNING 1/2, 3120 RPM, peers median 5460
# 10:03 db02 FAN3: WARNING   (OK -> WARNING) 3000 RPM, peers median 5460
# 10:04   (held) FAN3: CRITICAL 1/2, 1260 RPM < 1500
# 10:05 db02 FAN3: CRITICAL  (WARNING -> CRITICAL) 1140 RPM < 1500
# 10:06   (held) FAN3: UNKNOWN 1/2, No Reading
# 10:07   (held) FAN3: OK 1/2, 5280 RPM
# 10:08 db02 FAN3: RECOVERED (CRITICAL -> OK) 5340 RPM
# final: FAN1=OK, FAN2=OK, FAN3=OK, FAN4=OK
