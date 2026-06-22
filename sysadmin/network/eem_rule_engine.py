"""EEM-style event -> action engine: simulate applets against a syslog stream

Cisco's Embedded Event Manager runs "applets" on the switch: an event
(a syslog pattern, optionally "occurs N period S") triggers numbered
actions (run a CLI command, log a message). Testing an applet on a live
core switch is how people find out it fires 400 times during a flap. This
simulator parses the applet config text and replays a captured syslog
stream through it, so the behaviour can be reviewed before deployment.

Behaviour worth knowing, all reproduced here:
- `occurs 3 period 60` fires only when 3 matches fall inside 60 seconds;
- `ratelimit 300` suppresses re-triggering for 300 s after a run;
- action labels are sorted as *strings*: 1, 10, 2 -- not 1, 2, 10. Use
  labels like 010/020 or 1.0/2.0 so the order is the one you meant.

`$_iface` is a shortcut of this simulator; a real applet extracts it from
$_syslog_msg with `action ... regexp`.
"""

import re
import shlex
from collections import deque
from dataclasses import dataclass, field

APPLETS = """\
event manager applet UPLINK-DOWN
 event syslog pattern "Interface TenGigabitEthernet1/1/[12], changed state to down" ratelimit 300
 action 1 cli command "enable"
 action 2 cli command "show interfaces $_iface | include rate|errors"
 action 10 syslog msg "uplink $_iface down: interface state captured"
event manager applet BPDUGUARD-STORM
 event syslog pattern "%SPANTREE-2-BLOCK_BPDUGUARD" occurs 3 period 60
 action 010 syslog msg "3+ bpduguard err-disables in 60s, possible loop on access layer"
 action 020 cli command "show interfaces status err-disabled"
"""

SYSLOG = """\
00:00:05 %LINK-3-UPDOWN: Interface TenGigabitEthernet1/1/1, changed state to down
00:00:09 %LINK-3-UPDOWN: Interface TenGigabitEthernet1/1/1, changed state to up
00:00:41 %LINK-3-UPDOWN: Interface TenGigabitEthernet1/1/1, changed state to down
00:01:10 %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/12 with BPDU Guard enabled
00:01:30 %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/13 with BPDU Guard enabled
00:02:40 %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/14 with BPDU Guard enabled
00:02:52 %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/15 with BPDU Guard enabled
00:02:59 %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/16 with BPDU Guard enabled
00:06:02 %LINK-3-UPDOWN: Interface TenGigabitEthernet1/1/2, changed state to down
"""

FAKE_CLI = {
    "enable": "",
    "show interfaces TenGigabitEthernet1/1/1 | include rate|errors": "  5 minute input rate 0 bits/sec",
    "show interfaces TenGigabitEthernet1/1/2 | include rate|errors": "  5 minute input rate 0 bits/sec",
    "show interfaces status err-disabled": "Gi1/0/12  bpduguard  (+4 more)",
}


@dataclass
class Applet:
    name: str
    pattern: re.Pattern[str] | None = None
    occurs: int = 1
    period: int = 0
    ratelimit: int = 0
    actions: dict[str, tuple[str, str]] = field(default_factory=dict)
    hits: deque[int] = field(default_factory=deque)
    last_run: int | None = None


def parse_applets(text: str) -> list[Applet]:
    applets: list[Applet] = []
    for line in text.splitlines():
        words = shlex.split(line)
        if words[:3] == ["event", "manager", "applet"]:
            applets.append(Applet(words[3]))
        elif words[:3] == ["event", "syslog", "pattern"]:
            a = applets[-1]
            a.pattern = re.compile(words[3])
            options = dict(zip(words[4::2], map(int, words[5::2])))
            a.occurs, a.period, a.ratelimit = options.get("occurs", 1), options.get("period", 0), \
                options.get("ratelimit", 0)
        elif words[0] == "action":
            label, kind, arg = words[1], " ".join(words[2:4]), words[4]
            applets[-1].actions[label] = (kind, arg)
    return applets


def seconds(stamp: str) -> int:
    h, m, s = map(int, stamp.split(":"))
    return h * 3600 + m * 60 + s


def handle(applet: Applet, now: int, message: str) -> list[str]:
    if not (applet.pattern and applet.pattern.search(message)):
        return []
    applet.hits.append(now)
    while applet.period and applet.hits and now - applet.hits[0] > applet.period:
        applet.hits.popleft()
    if len(applet.hits) < applet.occurs:
        return [f"{applet.name}: match {len(applet.hits)}/{applet.occurs} within {applet.period}s"]
    if applet.last_run is not None and now - applet.last_run < applet.ratelimit:
        return [f"{applet.name}: suppressed by ratelimit ({now - applet.last_run}s < {applet.ratelimit}s)"]
    applet.last_run, applet.hits = now, deque()
    iface = m.group(0) if (m := re.search(r"(?:Ten)?GigabitEthernet\S+?(?=,)", message)) else ""
    out = [f"{applet.name}: TRIGGERED"]
    for label in sorted(applet.actions):  # string order, like EEM
        kind, arg = applet.actions[label]
        arg = arg.replace("$_iface", iface)
        if kind == "cli command":
            result = FAKE_CLI.get(arg, "% Invalid input")
            out.append(f"  action {label:<3} cli    {arg}" + (f"\n{'':14}-> {result}" if result else ""))
        else:
            out.append(f"  action {label:<3} syslog %HA_EM-6-LOG: {applet.name}: {arg}")
    return out


def main() -> None:
    applets = parse_applets(APPLETS)
    for a in applets:
        print(f"{a.name}: occurs {a.occurs} period {a.period}s ratelimit {a.ratelimit}s, "
              f"action order {list(sorted(a.actions))}")
    print()
    for line in SYSLOG.splitlines():
        stamp, message = line.split(" ", 1)
        for applet in applets:
            for out in handle(applet, seconds(stamp), message):
                print(f"{stamp} {out}")


if __name__ == "__main__":
    main()

# Output:
# UPLINK-DOWN: occurs 1 period 0s ratelimit 300s, action order ['1', '10', '2']
# BPDUGUARD-STORM: occurs 3 period 60s ratelimit 0s, action order ['010', '020']
#
# 00:00:05 UPLINK-DOWN: TRIGGERED
# 00:00:05   action 1   cli    enable
# 00:00:05   action 10  syslog %HA_EM-6-LOG: UPLINK-DOWN: uplink TenGigabitEthernet1/1/1 down: interface state captured
# 00:00:05   action 2   cli    show interfaces TenGigabitEthernet1/1/1 | include rate|errors
#               ->   5 minute input rate 0 bits/sec
# 00:00:41 UPLINK-DOWN: suppressed by ratelimit (36s < 300s)
# 00:01:10 BPDUGUARD-STORM: match 1/3 within 60s
# 00:01:30 BPDUGUARD-STORM: match 2/3 within 60s
# 00:02:40 BPDUGUARD-STORM: match 1/3 within 60s
# 00:02:52 BPDUGUARD-STORM: match 2/3 within 60s
# 00:02:59 BPDUGUARD-STORM: TRIGGERED
# 00:02:59   action 010 syslog %HA_EM-6-LOG: BPDUGUARD-STORM: 3+ bpduguard err-disables in 60s, possible loop on access layer
# 00:02:59   action 020 cli    show interfaces status err-disabled
#               -> Gi1/0/12  bpduguard  (+4 more)
# 00:06:02 UPLINK-DOWN: TRIGGERED
# 00:06:02   action 1   cli    enable
# 00:06:02   action 10  syslog %HA_EM-6-LOG: UPLINK-DOWN: uplink TenGigabitEthernet1/1/2 down: interface state captured
# 00:06:02   action 2   cli    show interfaces TenGigabitEthernet1/1/2 | include rate|errors
#               ->   5 minute input rate 0 bits/sec
