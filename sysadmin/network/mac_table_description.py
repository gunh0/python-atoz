"""Access-port descriptions from `show mac address-table` + an inventory map

Servers and printers do not speak CDP/LLDP, but their MAC addresses are in
the asset inventory, and the switch knows which port each MAC was learned
on. Joining the two gives a description for every access port. Doing it
blindly, one description per MAC line, produces confident nonsense:

- the uplink/trunk learns every MAC behind it, so it gets "described" as
  whichever host happened to be printed last;
- a port with an IP phone and a PC has two MACs (voice + data VLAN);
- a hypervisor port carries many VM MACs, none of which is "the" device;
- MACs missing from the inventory, and CPU/static entries, must be skipped;
- the inventory writes 00:50:56:A1:00:01, IOS writes 0050.56a1.0001.

The careful version groups by port first and only writes a description when
exactly one known, non-phone MAC is on an access port.
"""

import re
from collections import defaultdict

from _ios import long_ifname

MAC_TABLE = """\
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
 All    0180.c200.0000    STATIC      CPU
  10    0050.56a1.0001    DYNAMIC     Gi1/0/5
  10    3cec.ef12.3a40    DYNAMIC     Gi1/0/6
  10    0c42.a1b0.0007    DYNAMIC     Gi1/0/7
  20    0c42.a1b0.0010    DYNAMIC     Gi1/0/12
 110    0056.2b0a.1f3c    DYNAMIC     Gi1/0/12
  30    0050.56a1.0101    DYNAMIC     Gi1/0/20
  30    0050.56a1.0102    DYNAMIC     Gi1/0/20
  30    0050.56a1.0103    DYNAMIC     Gi1/0/20
  10    a4bb.6d00.5511    DYNAMIC     Te1/1/1
  10    3cec.ef12.9910    DYNAMIC     Te1/1/1
  20    0c42.a1b0.0042    DYNAMIC     Te1/1/1
  20    9c8e.99c4.0e21    DYNAMIC     Te1/1/1
Total Mac Addresses for this criterion: 14
"""

# Exported from the asset database (format as the export writes it).
INVENTORY = """\
mac,hostname,role
00:50:56:A1:00:01,mon01,server
3C:EC:EF:12:3A:40,bk-nas02,storage
0C:42:A1:B0:00:10,ws-kim-3f,workstation
00:56:2B:0A:1F:3C,SEP00562B0A1F3C,phone
00:50:56:A1:01:01,vm-web11,vm
00:50:56:A1:01:02,vm-web12,vm
9C:8E:99:C4:0E:21,prn-3f-east,printer
"""

# Copied from the running-config, so long names; the MAC table uses short ones.
TRUNKS = {"TenGigabitEthernet1/1/1"}  # never describe trunks from MACs
VOICE_VLANS = {110}


def normalise_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-f]", "", mac.lower())
    if len(digits) != 12:
        raise ValueError(f"not a MAC: {mac!r}")
    return ".".join(digits[i:i + 4] for i in range(0, 12, 4))


def parse_mac_table(text: str) -> list[tuple[int, str, str]]:
    rows = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+([0-9a-f.]{14})\s+DYNAMIC\s+(\S+)\s*$", line)
        if m:  # skips headers, "All" VLAN CPU entries and the total line
            rows.append((int(m.group(1)), normalise_mac(m.group(2)), m.group(3)))
    return rows


def parse_inventory(text: str) -> dict[str, tuple[str, str]]:
    lines = text.splitlines()[1:]
    return {normalise_mac(mac): (host, role) for mac, host, role in (l.split(",") for l in lines)}


def blind(rows, inventory) -> dict[str, str]:
    desc = {}
    for _, mac, port in rows:
        if mac in inventory:
            desc[port] = inventory[mac][0]  # last one wins
    return desc


def careful(rows, inventory) -> tuple[dict[str, str], dict[str, str]]:
    by_port: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for vlan, mac, port in rows:
        by_port[port].append((vlan, mac))
    desc, skipped = {}, {}
    for port, entries in by_port.items():
        if long_ifname(port) in TRUNKS:
            skipped[port] = f"trunk, {len(entries)} MACs learned"
            continue
        data = [(v, m) for v, m in entries if v not in VOICE_VLANS
                and inventory.get(m, ("", ""))[1] != "phone"]
        if len(data) > 1:
            skipped[port] = f"{len(data)} MACs on data VLANs (hypervisor or hub?)"
        elif not data:
            skipped[port] = "only a phone"
        elif data[0][1] not in inventory:
            skipped[port] = f"{data[0][1]} not in inventory"
        else:
            host, role = inventory[data[0][1]]
            phone = " +phone" if len(entries) > len(data) else ""
            desc[port] = f"{host} ({role}){phone}"
    return desc, skipped


def main() -> None:
    rows = parse_mac_table(MAC_TABLE)
    inventory = parse_inventory(INVENTORY)
    print(f"{len(rows)} dynamic entries, {len(inventory)} inventory MACs")

    print()
    print("blind join, one description per MAC line:")
    for port, text in blind(rows, inventory).items():
        print(f"  {port:<9} {text}")

    desc, skipped = careful(rows, inventory)
    print()
    print("careful join:")
    for port, text in desc.items():
        print(f"interface {long_ifname(port)}\n description {text}")
    for port, why in skipped.items():
        print(f"! {port}: skipped, {why}")


if __name__ == "__main__":
    main()

# Output:
# 12 dynamic entries, 7 inventory MACs
#
# blind join, one description per MAC line:
#   Gi1/0/5   mon01
#   Gi1/0/6   bk-nas02
#   Gi1/0/12  SEP00562B0A1F3C
#   Gi1/0/20  vm-web12
#   Te1/1/1   prn-3f-east
#
# careful join:
# interface GigabitEthernet1/0/5
#  description mon01 (server)
# interface GigabitEthernet1/0/6
#  description bk-nas02 (storage)
# interface GigabitEthernet1/0/12
#  description ws-kim-3f (workstation) +phone
# ! Gi1/0/7: skipped, 0c42.a1b0.0007 not in inventory
# ! Gi1/0/20: skipped, 3 MACs on data VLANs (hypervisor or hub?)
# ! Te1/1/1: skipped, trunk, 4 MACs learned
