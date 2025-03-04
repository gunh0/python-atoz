"""SNMP: translate numeric OIDs to IF-MIB names and back, without net-snmp MIBs

`snmpwalk -On` prints numeric OIDs, which is what you want in scripts (no MIB
files needed, no ambiguity), but nobody can read `.1.3.6.1.2.1.31.1.1.1.6.3`
in a report. The usual fix is a small table of the columns you care about and
a longest-prefix lookup: an instance OID is <column OID>.<index>, so strip
the longest known prefix and what is left is the index (ifIndex here).

Keep OIDs as tuples of ints, not strings. As strings, "1.3.6.1.2.1.2.2.1.1"
is a prefix of "1.3.6.1.2.1.2.2.1.10" and sorting puts ".10" before ".2";
both bugs show up as wrong columns in your graphs.
"""

# name -> (module, column OID). The three sys* objects live in SNMPv2-MIB.
MIB = {
    "sysDescr": ("SNMPv2-MIB", "1.3.6.1.2.1.1.1"),
    "sysUpTime": ("SNMPv2-MIB", "1.3.6.1.2.1.1.3"),
    "sysName": ("SNMPv2-MIB", "1.3.6.1.2.1.1.5"),
    "ifIndex": ("IF-MIB", "1.3.6.1.2.1.2.2.1.1"),
    "ifDescr": ("IF-MIB", "1.3.6.1.2.1.2.2.1.2"),
    "ifType": ("IF-MIB", "1.3.6.1.2.1.2.2.1.3"),
    "ifMtu": ("IF-MIB", "1.3.6.1.2.1.2.2.1.4"),
    "ifSpeed": ("IF-MIB", "1.3.6.1.2.1.2.2.1.5"),
    "ifAdminStatus": ("IF-MIB", "1.3.6.1.2.1.2.2.1.7"),
    "ifOperStatus": ("IF-MIB", "1.3.6.1.2.1.2.2.1.8"),
    "ifInOctets": ("IF-MIB", "1.3.6.1.2.1.2.2.1.10"),
    "ifInErrors": ("IF-MIB", "1.3.6.1.2.1.2.2.1.14"),
    "ifOutOctets": ("IF-MIB", "1.3.6.1.2.1.2.2.1.16"),
    "ifOutErrors": ("IF-MIB", "1.3.6.1.2.1.2.2.1.20"),
    "ifName": ("IF-MIB", "1.3.6.1.2.1.31.1.1.1.1"),
    "ifHCInOctets": ("IF-MIB", "1.3.6.1.2.1.31.1.1.1.6"),
    "ifHCOutOctets": ("IF-MIB", "1.3.6.1.2.1.31.1.1.1.10"),
    "ifHighSpeed": ("IF-MIB", "1.3.6.1.2.1.31.1.1.1.15"),
    "ifAlias": ("IF-MIB", "1.3.6.1.2.1.31.1.1.1.18"),
}

Oid = tuple[int, ...]


def oid(text: str) -> Oid:
    return tuple(int(part) for part in text.strip(".").split("."))


def dotted(value: Oid) -> str:
    return ".".join(map(str, value))


BY_OID: dict[Oid, str] = {oid(num): name for name, (_, num) in MIB.items()}
BY_NAME: dict[str, Oid] = {name: oid(num) for name, (_, num) in MIB.items()}
LONGEST = max(len(o) for o in BY_OID)


def to_name(numeric: str) -> str:
    """'.1.3.6.1.2.1.31.1.1.1.6.3' -> 'IF-MIB::ifHCInOctets.3'"""
    full = oid(numeric)
    for size in range(min(len(full), LONGEST), 0, -1):
        name = BY_OID.get(full[:size])
        if name:
            rest = full[size:]
            module = MIB[name][0]
            return f"{module}::{name}" + (f".{dotted(rest)}" if rest else "")
    return "." + dotted(full)


def to_numeric(name: str) -> str:
    """'IF-MIB::ifHCInOctets.3' -> '.1.3.6.1.2.1.31.1.1.1.6.3'"""
    column, _, index = name.rpartition("::")[2].partition(".")
    base = BY_NAME[column]
    return "." + dotted(base + (oid(index) if index else ()))


def naive_to_name(numeric: str) -> str:
    """The string-prefix version people write first. Do not use."""
    text = numeric.strip(".")
    for name, (_, column) in MIB.items():
        if text.startswith(column):
            return f"{name}{text[len(column):]}"
    return numeric


# Self-written `snmpwalk -v2c -c public -On 192.0.2.10 ifTable/ifXTable` excerpt.
WALK = """\
.1.3.6.1.2.1.1.5.0 = STRING: edge-sw02
.1.3.6.1.2.1.2.2.1.2.1 = STRING: GigabitEthernet1/0/1
.1.3.6.1.2.1.2.2.1.2.2 = STRING: GigabitEthernet1/0/2
.1.3.6.1.2.1.2.2.1.10.1 = Counter32: 3735928559
.1.3.6.1.2.1.2.2.1.10.2 = Counter32: 120044
.1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.8.2 = INTEGER: down(2)
.1.3.6.1.2.1.31.1.1.1.6.1 = Counter64: 81604378607
.1.3.6.1.2.1.31.1.1.1.18.1 = STRING: uplink to core-sw01
.1.3.6.1.4.1.9.9.13.1.3.1.3.1 = Gauge32: 31
"""


def main() -> None:
    rows = []
    for line in WALK.splitlines():
        left, _, value = line.partition(" = ")
        rows.append((oid(left), to_name(left), value))

    print("walk order as received, translated:")
    for _, name, value in rows:
        print(f"  {name:<32} {value}")

    print()
    print("sorted as strings vs as OID tuples (first four):")
    as_str = sorted(dotted(o) for o, _, _ in rows)[1:5]
    as_tuple = [dotted(o) for o in sorted(o for o, _, _ in rows)][1:5]
    for s, t in zip(as_str, as_tuple):
        print(f"  {s:<26} {t}")

    print()
    sample = ".1.3.6.1.2.1.2.2.1.10.1"
    print(f"naive string prefix: {sample} -> {naive_to_name(sample)}")
    print(f"tuple prefix:        {sample} -> {to_name(sample)}")

    print()
    for name in ("IF-MIB::ifHCInOctets.3", "IF-MIB::ifAlias.12", "SNMPv2-MIB::sysName.0"):
        back = to_name(to_numeric(name))
        print(f"round trip {name:<25} -> {to_numeric(name):<30} -> {back}")


if __name__ == "__main__":
    main()

# Output:
# walk order as received, translated:
#   SNMPv2-MIB::sysName.0            STRING: edge-sw02
#   IF-MIB::ifDescr.1                STRING: GigabitEthernet1/0/1
#   IF-MIB::ifDescr.2                STRING: GigabitEthernet1/0/2
#   IF-MIB::ifInOctets.1             Counter32: 3735928559
#   IF-MIB::ifInOctets.2             Counter32: 120044
#   IF-MIB::ifIndex.1                INTEGER: 1
#   IF-MIB::ifOperStatus.2           INTEGER: down(2)
#   IF-MIB::ifHCInOctets.1           Counter64: 81604378607
#   IF-MIB::ifAlias.1                STRING: uplink to core-sw01
#   .1.3.6.1.4.1.9.9.13.1.3.1.3.1    Gauge32: 31
#
# sorted as strings vs as OID tuples (first four):
#   1.3.6.1.2.1.2.2.1.1.1      1.3.6.1.2.1.2.2.1.1.1
#   1.3.6.1.2.1.2.2.1.10.1     1.3.6.1.2.1.2.2.1.2.1
#   1.3.6.1.2.1.2.2.1.10.2     1.3.6.1.2.1.2.2.1.2.2
#   1.3.6.1.2.1.2.2.1.2.1      1.3.6.1.2.1.2.2.1.8.2
#
# naive string prefix: .1.3.6.1.2.1.2.2.1.10.1 -> ifIndex0.1
# tuple prefix:        .1.3.6.1.2.1.2.2.1.10.1 -> IF-MIB::ifInOctets.1
#
# round trip IF-MIB::ifHCInOctets.3    -> .1.3.6.1.2.1.31.1.1.1.6.3      -> IF-MIB::ifHCInOctets.3
# round trip IF-MIB::ifAlias.12        -> .1.3.6.1.2.1.31.1.1.1.18.12    -> IF-MIB::ifAlias.12
# round trip SNMPv2-MIB::sysName.0     -> .1.3.6.1.2.1.1.5.0             -> SNMPv2-MIB::sysName.0
