"""Classify switch ports from `show interfaces status` (fixed-width columns)

Before cleaning up a switch you want the ports in buckets: uplinks/trunks,
port-channels, access ports in use, unused access ports, admin-down,
err-disabled, empty optic slots, and anything negotiating badly (half
duplex, or a gigabit port stuck at 100 Mbit/s -- usually a bad cable).

`show interfaces status` is a fixed-width table, and the Name column is free
text: it can be empty or contain spaces, so `line.split()` shifts every
later column. Take the column start offsets from the header line instead and
slice each row. IOS also truncates the Name to its column width; do not
expect descriptions to round-trip from this output.
"""

from collections import defaultdict

STATUS = """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   mon01              connected    10         a-full a-1000 10/100/1000BaseTX
Gi1/0/2                      notconnect   10           auto   auto 10/100/1000BaseTX
Gi1/0/3   old printer 2f     disabled     20           auto   auto 10/100/1000BaseTX
Gi1/0/4                      notconnect   10           auto   auto 10/100/1000BaseTX
Gi1/0/12  ws-kim-3f (workst  connected    20         a-full a-1000 10/100/1000BaseTX
Gi1/0/13  lab-pc-07          connected    20         a-half  a-100 10/100/1000BaseTX
Gi1/0/24  esxi03 vmnic2      connected    trunk      a-full a-1000 10/100/1000BaseTX
Gi1/0/47                     err-disabled 10           auto   auto 10/100/1000BaseTX
Te1/1/1   core-sw01:Te1/0/17 connected    trunk        full    10G SFP-10GBase-SR
Te1/1/2   core-sw02:Te1/0/17 connected    trunk        full    10G SFP-10GBase-SR
Te1/1/3                      notconnect   1            full    10G Not Present
Twe1/0/1  storage-a ctrl0    connected    30           full    25G SFP-25GBase-SR
Po1       to core            connected    trunk      a-full  a-10G
"""

# Nominal speed in Mbit/s by interface name prefix.
NOMINAL_MBPS = {"Gi": 1000, "Te": 10000, "Po": None}
LONG_NAMES = {"Gi": "GigabitEthernet", "Te": "TenGigabitEthernet", "Po": "Port-channel"}


def column_slices(header: str) -> dict[str, slice]:
    names = header.split()
    starts = [header.index(name) for name in names]
    ends = starts[1:] + [None]
    return {name: slice(start, end) for name, start, end in zip(names, starts, ends)}


def parse_status(text: str) -> list[dict[str, str]]:
    header, *rows = text.splitlines()
    cols = column_slices(header)
    out = []
    for row in rows:
        # Duplex and Speed are right-aligned under their headers, so slicing them
        # by header offset cuts "a-full"; they never contain spaces, split instead.
        fixed = {name: row[s].strip() for name, s in cols.items() if name in ("Port", "Name", "Status", "Vlan")}
        tail = row[cols["Vlan"].stop:].split(None, 2)
        fixed.update(zip(("Duplex", "Speed", "Type"), tail + ["", "", ""]))
        out.append(fixed)
    return out


def prefix(port: str) -> str:
    return port.rstrip("0123456789/.").rstrip()


def classify(p: dict[str, str]) -> str:
    kind = prefix(p["Port"])
    if kind not in NOMINAL_MBPS:
        return "unknown type"
    if p["Status"] == "err-disabled":
        return "err-disabled"
    if p["Status"] == "disabled":
        return "admin down"
    if p["Type"] == "Not Present":
        return "empty optic slot"
    if kind == "Po":
        return "port-channel"
    if p["Vlan"] == "trunk":
        return "trunk"
    if p["Status"] == "notconnect":
        return "access unused"
    nominal = NOMINAL_MBPS[kind]
    speed = p["Speed"].removeprefix("a-")
    mbps = int(speed[:-1]) * 1000 if speed.endswith("G") else int(speed) if speed.isdigit() else None
    if "half" in p["Duplex"] or (mbps and nominal and mbps < nominal):
        return "access degraded link"
    return "access in use"


def main() -> None:
    ports = parse_status(STATUS)
    naive = STATUS.splitlines()[3].split()
    print(f"naive split of Gi1/0/3: status={naive[2]!r} vlan={naive[3]!r}")
    print(f"offset parse of Gi1/0/3: status={ports[2]['Status']!r} vlan={ports[2]['Vlan']!r}")
    print()
    buckets: dict[str, list[str]] = defaultdict(list)
    for p in ports:
        buckets[classify(p)].append(p["Port"])
    for name in sorted(buckets):
        print(f"{name:<21} {len(buckets[name]):>2}  {' '.join(buckets[name])}")

    degraded = [p for p in ports if classify(p) == "access degraded link"]
    for p in degraded:
        print(f"check cable: {p['Port']} ({p['Name']}) at {p['Duplex']} {p['Speed']}")

    print()
    print("! proposed cleanup for unused access ports")
    for port in buckets["access unused"]:
        kind = prefix(port)
        print(f"interface {LONG_NAMES[kind]}{port[len(kind):]}\n description UNUSED\n shutdown")


if __name__ == "__main__":
    main()

# Output:
# naive split of Gi1/0/3: status='printer' vlan='2f'
# offset parse of Gi1/0/3: status='disabled' vlan='20'
#
# access degraded link   1  Gi1/0/13
# access in use          2  Gi1/0/1 Gi1/0/12
# access unused          2  Gi1/0/2 Gi1/0/4
# admin down             1  Gi1/0/3
# empty optic slot       1  Te1/1/3
# err-disabled           1  Gi1/0/47
# port-channel           1  Po1
# trunk                  3  Gi1/0/24 Te1/1/1 Te1/1/2
# unknown type           1  Twe1/0/1
# check cable: Gi1/0/13 (lab-pc-07) at a-half a-100
#
# ! proposed cleanup for unused access ports
# interface GigabitEthernet1/0/2
#  description UNUSED
#  shutdown
# interface GigabitEthernet1/0/4
#  description UNUSED
#  shutdown
