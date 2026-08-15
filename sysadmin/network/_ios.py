"""Cisco interface-name helpers shared by the network examples.

IOS prints the same port as "TenGigabitEthernet1/1/1" (config, CDP) and
"Te1/1/1" (status tables, MAC table, logs). Every script that joins two of
those outputs needs to normalise names, and the CDP, MAC-table and
port-classifier examples each grew their own table -- which drifted: the
classifier did not know TwentyFiveGigE and reported Twe ports as "unknown".
One table, one place to add the next interface type.
"""

import re

# (long name, short name, nominal Mbit/s or None when it depends on the port)
INTERFACE_TYPES = [
    ("HundredGigE", "Hu", 100_000),
    ("FortyGigabitEthernet", "Fo", 40_000),
    ("TwentyFiveGigE", "Twe", 25_000),
    ("TenGigabitEthernet", "Te", 10_000),
    ("GigabitEthernet", "Gi", 1_000),
    ("FastEthernet", "Fa", 100),
    ("Ethernet", "Eth", None),  # NX-OS front panel ports, any speed
    ("Port-channel", "Po", None),
    ("Vlan", "Vl", None),
]
_BY_ALIAS = {alias.lower(): row for row in INTERFACE_TYPES for alias in row[:2]}
_NAME = re.compile(r"^([A-Za-z-]+)\s*(\d.*)$")


def split_ifname(name: str) -> tuple[tuple[str, str, int | None] | None, str]:
    """'Te1/1/1' -> (('TenGigabitEthernet', 'Te', 10000), '1/1/1')"""
    m = _NAME.match(name.strip())
    if not m:
        return None, name
    return _BY_ALIAS.get(m.group(1).lower()), m.group(2)


def short_ifname(name: str) -> str:
    kind, number = split_ifname(name)
    return f"{kind[1]}{number}" if kind else name


def long_ifname(name: str) -> str:
    kind, number = split_ifname(name)
    return f"{kind[0]}{number}" if kind else name


def nominal_mbps(name: str) -> int | None:
    kind, _ = split_ifname(name)
    return kind[2] if kind else None


def is_known(name: str) -> bool:
    return split_ifname(name)[0] is not None


def port_sort_key(name: str) -> list[str | int]:
    """Natural order: Gi1/0/2 before Gi1/0/12."""
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", name)]
