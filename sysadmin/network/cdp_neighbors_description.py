"""CDP neighbors -> `interface ... / description ...` config lines

Interface descriptions rot. CDP already knows what is plugged in where, so
generate the descriptions from `show cdp neighbors detail` and paste (or push)
the result. The detail form is the one to parse: the short `show cdp
neighbors` table wraps long device IDs onto two lines and truncates the
platform column.

Details that bite: entries are separated by a dashed line; the Device ID may
carry a domain ("core-sw01.example.net") or, on NX-OS, the serial number in
parentheses; the remote port is in "Port ID (outgoing port)". The output is
a proposal for review, never something to apply blindly -- IP phones and APs
come and go, and a description should only describe infrastructure links.
"""

import re
from dataclasses import dataclass

from _ios import port_sort_key, short_ifname

CDP_DETAIL = """\
-------------------------
Device ID: core-sw01.example.net
Entry address(es):
  IP address: 10.0.0.1
Platform: cisco WS-C3850-24XS,  Capabilities: Router Switch IGMP
Interface: TenGigabitEthernet1/1/1,  Port ID (outgoing port): TenGigabitEthernet1/0/17
Holdtime : 151 sec

Version :
Cisco IOS Software [Fuji], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.9.8

advertisement version: 2
Native VLAN: 1
Duplex: full

-------------------------
Device ID: core-sw02.example.net
Entry address(es):
  IP address: 10.0.0.2
Platform: cisco WS-C3850-24XS,  Capabilities: Router Switch IGMP
Interface: TenGigabitEthernet1/1/2,  Port ID (outgoing port): TenGigabitEthernet1/0/17
Holdtime : 149 sec

Version :
Cisco IOS Software [Fuji], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.9.8

advertisement version: 2
Native VLAN: 1
Duplex: full

-------------------------
Device ID: nx-dc-leaf07(FDO21120ABC)
Entry address(es):
  IP address: 10.0.8.7
Platform: N9K-C93180YC-EX,  Capabilities: Router Switch IGMP Filtering Supports-STP-Dispute
Interface: GigabitEthernet1/0/48,  Port ID (outgoing port): Ethernet1/49
Holdtime : 170 sec

-------------------------
Device ID: SEP00562B0A1F3C
Entry address(es):
  IP address: 10.20.5.141
Platform: Cisco IP Phone 8845,  Capabilities: Host Phone Two-port Mac Relay
Interface: GigabitEthernet1/0/12,  Port ID (outgoing port): Port 1
Holdtime : 133 sec

-------------------------
Device ID: ap-3f-east.example.net
Entry address(es):
  IP address: 10.30.0.44
Platform: cisco C9120AXI-A,  Capabilities: Router Trans-Bridge
Interface: GigabitEthernet1/0/30,  Port ID (outgoing port): GigabitEthernet0
Holdtime : 98 sec
"""

INFRA_CAPABILITIES = {"Router", "Switch"}
# Cisco APs advertise "Router Trans-Bridge", phones "Host Phone": not uplinks.
EDGE_CAPABILITIES = {"Phone", "Trans-Bridge", "Host"}


@dataclass
class Neighbor:
    device: str
    platform: str
    capabilities: set[str]
    local_port: str
    remote_port: str


def hostname(device_id: str) -> str:
    device_id = re.sub(r"\(.*\)$", "", device_id)  # NX-OS: name(SERIAL)
    return device_id.split(".")[0]


def parse_cdp_detail(text: str) -> list[Neighbor]:
    neighbors = []
    for block in re.split(r"^-{10,}$", text, flags=re.M):
        fields = {}
        if m := re.search(r"^Device ID: *(.+)$", block, re.M):
            fields["device"] = m.group(1).strip()
        if m := re.search(r"^Platform: *(.+?), +Capabilities: *(.*)$", block, re.M):
            fields["platform"], fields["caps"] = m.group(1).strip(), m.group(2)
        if m := re.search(r"^Interface: *(\S+?), +Port ID \(outgoing port\): *(.+)$", block, re.M):
            fields["local"], fields["remote"] = m.group(1), m.group(2).strip()
        if len(fields) == 5:
            neighbors.append(Neighbor(fields["device"], fields["platform"],
                                      set(fields["caps"].split()), fields["local"], fields["remote"]))
    return neighbors


def description_config(neighbors: list[Neighbor]) -> tuple[list[str], list[str]]:
    config, skipped = [], []
    for n in sorted(neighbors, key=lambda n: port_sort_key(n.local_port)):
        if not n.capabilities & INFRA_CAPABILITIES or n.capabilities & EDGE_CAPABILITIES:
            skipped.append(f"{short_ifname(n.local_port)}: {n.device} ({n.platform}) is not infrastructure")
            continue
        text = f"{hostname(n.device)}:{short_ifname(n.remote_port)}"
        config += [f"interface {n.local_port}", f" description {text}"]
    return config, skipped


def main() -> None:
    neighbors = parse_cdp_detail(CDP_DETAIL)
    print(f"parsed {len(neighbors)} neighbors")
    config, skipped = description_config(neighbors)
    print("\n".join(config))
    print()
    for line in skipped:
        print("! skipped", line)


if __name__ == "__main__":
    main()

# Output:
# parsed 5 neighbors
# interface GigabitEthernet1/0/48
#  description nx-dc-leaf07:Eth1/49
# interface TenGigabitEthernet1/1/1
#  description core-sw01:Te1/0/17
# interface TenGigabitEthernet1/1/2
#  description core-sw02:Te1/0/17
#
# ! skipped Gi1/0/12: SEP00562B0A1F3C (Cisco IP Phone 8845) is not infrastructure
# ! skipped Gi1/0/30: ap-3f-east.example.net (cisco C9120AXI-A) is not infrastructure
