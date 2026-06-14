"""Fan monitor v3: rules as a table, immediate escalation, CPU temp correlation

v2's evaluate() was an if/elif chain, and the next request -- "a slow fan
is only urgent if the CPU behind it is getting hot" -- needed readings from
a second command (`ipmitool sdr type Temperature`) inside that chain. v3
turns every check into a Rule(name, severity, test) entry. All rules run,
the worst match wins, and the alert names every rule that matched, so the
on-call engineer sees *why* without reading the code.

The second change is a fix to v2's debounce: it also delayed CRITICAL by a
poll. Now escalation to CRITICAL is immediate, everything else (including
recovery) still needs DEBOUNCE consecutive polls.
"""

from collections.abc import Callable
from dataclasses import dataclass
from statistics import median

WARN_RPM, CRIT_RPM = 2500, 1500
PEER_RATIO = 0.6
HOT_C = 80
DEBOUNCE = 2
RANK = {"OK": 0, "UNKNOWN": 1, "WARNING": 2, "CRITICAL": 3}


def sdr_fans(*readings: str) -> str:
    """Render `ipmitool sdr type Fan` output in the BMC's exact format."""
    return "".join(f"FAN{n:<14}| {0x2f + n:02x}h | {'ns' if r == 'No Reading' else 'ok':<3} | "
                   f"29.{n} | {r}\n" for n, r in enumerate(readings, start=1))


def sdr_temps(cpu1: int, cpu2: int) -> str:
    """Render `ipmitool sdr type Temperature` output."""
    return (f"CPU1 Temp        | 01h | ok  |  3.1 | {cpu1} degrees C\n"
            f"CPU2 Temp        | 02h | ok  |  3.2 | {cpu2} degrees C\n")


# db02, one poll per minute: (fans, temperatures). FAN3/FAN4 cool CPU2 on this board.
POLLS = [
    ("10:00", sdr_fans("5460 RPM", "5520 RPM", "5400 RPM", "5520 RPM"), sdr_temps(58, 61)),
    ("10:01", sdr_fans("5460 RPM", "2280 RPM", "5340 RPM", "5520 RPM"), sdr_temps(58, 61)),
    ("10:02", sdr_fans("5400 RPM", "5520 RPM", "3120 RPM", "5460 RPM"), sdr_temps(59, 70)),
    ("10:03", sdr_fans("5460 RPM", "5460 RPM", "3000 RPM", "5520 RPM"), sdr_temps(59, 77)),
    ("10:04", sdr_fans("5460 RPM", "5520 RPM", "2940 RPM", "5520 RPM"), sdr_temps(60, 84)),
    ("10:05", sdr_fans("5400 RPM", "5520 RPM", "No Reading", "5460 RPM"), sdr_temps(60, 86)),
    ("10:06", sdr_fans("5460 RPM", "5520 RPM", "5280 RPM", "5520 RPM"), sdr_temps(59, 72)),
    ("10:07", sdr_fans("5460 RPM", "5460 RPM", "5340 RPM", "5520 RPM"), sdr_temps(58, 63)),
]
COOLS = {"FAN1": "CPU1 Temp", "FAN2": "CPU1 Temp", "FAN3": "CPU2 Temp", "FAN4": "CPU2 Temp"}


def parse_sdr(text: str) -> dict[str, int | None]:
    """name -> integer reading (RPM or degrees C), None for 'No Reading'."""
    out = {}
    for line in text.splitlines():
        cols = [c.strip() for c in line.split("|")]
        if len(cols) == 5:
            value = cols[4].split()[0]
            out[cols[0]] = int(float(value)) if value[0].isdigit() else None
    return out


@dataclass(frozen=True)
class Ctx:
    fan: str
    rpm: int | None
    fans: dict[str, int | None]
    temps: dict[str, int | None]

    @property
    def peers(self) -> list[int]:
        return [v for n, v in self.fans.items() if n != self.fan and v is not None]


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    test: Callable[[Ctx], bool]


def _slower_than_peers(c: Ctx) -> bool:
    return c.rpm is not None and bool(c.peers) and c.rpm < PEER_RATIO * median(c.peers)


def _hot_and_slow(c: Ctx) -> bool:
    temp = c.temps.get(COOLS.get(c.fan, ""))
    slow = c.rpm is None or c.rpm < WARN_RPM or _slower_than_peers(c)
    return slow and temp is not None and temp >= HOT_C


RULES = [
    Rule("no-reading", "UNKNOWN", lambda c: c.rpm is None),
    Rule("below-critical", "CRITICAL", lambda c: c.rpm is not None and c.rpm < CRIT_RPM),
    Rule("below-warning", "WARNING", lambda c: c.rpm is not None and c.rpm < WARN_RPM),
    Rule("slower-than-peers", "WARNING", _slower_than_peers),
    Rule("hot-and-slow", "CRITICAL", _hot_and_slow),
]


def evaluate(fans, temps) -> dict[str, tuple[str, list[str]]]:
    out = {}
    for fan, rpm in fans.items():
        hits = [r for r in RULES if r.test(Ctx(fan, rpm, fans, temps))]
        worst = max((r.severity for r in hits), key=RANK.__getitem__, default="OK")
        out[fan] = (worst, [r.name for r in hits])
    return out


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
    state.streak = state.streak + 1 if observed == state.candidate else 1
    state.candidate = observed
    if observed == "CRITICAL" or state.streak >= DEBOUNCE:
        state.reported, state.streak = observed, 0
        return True
    return False


def main() -> None:
    states: dict[str, FanState] = {}
    for stamp, fan_text, temp_text in POLLS:
        fans, temps = parse_sdr(fan_text), parse_sdr(temp_text)
        for fan, (observed, rules) in evaluate(fans, temps).items():
            state = states.setdefault(fan, FanState())
            before = state.reported
            reading = "no reading" if fans[fan] is None else f"{fans[fan]} RPM"
            why = f"{reading}, {COOLS[fan]} {temps[COOLS[fan]]} C"
            why += f" [{', '.join(rules)}]" if rules else ""
            if step(state, observed):
                verb = "RECOVERED" if observed == "OK" else observed
                print(f"{stamp} db02 {fan}: {verb:<9} ({before} -> {observed}) {why}")
            elif observed != state.reported:
                print(f"{stamp}   (held) {fan}: {observed} {state.streak}/{DEBOUNCE}, {why}")
    print("final:", ", ".join(f"{n}={s.reported}" for n, s in states.items()))
    print("rules:", ", ".join(f"{r.name}={r.severity}" for r in RULES))


if __name__ == "__main__":
    main()

# Output:
# 10:01   (held) FAN2: WARNING 1/2, 2280 RPM, CPU1 Temp 58 C [below-warning, slower-than-peers]
# 10:02   (held) FAN3: WARNING 1/2, 3120 RPM, CPU2 Temp 70 C [slower-than-peers]
# 10:03 db02 FAN3: WARNING   (OK -> WARNING) 3000 RPM, CPU2 Temp 77 C [slower-than-peers]
# 10:04 db02 FAN3: CRITICAL  (WARNING -> CRITICAL) 2940 RPM, CPU2 Temp 84 C [slower-than-peers, hot-and-slow]
# 10:06   (held) FAN3: OK 1/2, 5280 RPM, CPU2 Temp 72 C
# 10:07 db02 FAN3: RECOVERED (CRITICAL -> OK) 5340 RPM, CPU2 Temp 63 C
# final: FAN1=OK, FAN2=OK, FAN3=OK, FAN4=OK
# rules: no-reading=UNKNOWN, below-critical=CRITICAL, below-warning=WARNING, slower-than-peers=WARNING, hot-and-slow=CRITICAL
