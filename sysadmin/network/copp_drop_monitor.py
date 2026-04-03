"""CoPP: watch control-plane policing drops between two snapshots

Control Plane Policing rate-limits traffic punted to the switch CPU, per
class (routing protocols, management, ARP, everything else). Drops in the
ARP or "undesirable" class during a broadcast storm are CoPP doing its job;
drops in the routing class mean BGP/OSPF packets are being thrown away and
adjacencies are about to flap. So the per-class delta matters, not the
lifetime totals `show policy-map control-plane` prints.

The output is a block per class-map with "conformed N packets" and
"exceeded N packets" lines under the police action. Parse both snapshots,
subtract, and alert per class with its own threshold. If any counter went
down, someone ran `clear counters` (or the box reloaded): skip that class
for this interval rather than reporting a negative rate.
"""

import re

SNAPSHOT_1 = """\
 Control Plane

  Service-policy input: COPP-POLICY

    Class-map: COPP-ROUTING (match-any)
      18233412 packets, 1786874376 bytes
      5 minute offered rate 3000 bps, drop rate 0000 bps
      Match: access-group name ACL-COPP-ROUTING
      police:
          cir 2000000 bps, bc 62500 bytes
        conformed 18233412 packets, 1786874376 bytes; actions:
          transmit
        exceeded 0 packets, 0 bytes; actions:
          drop

    Class-map: COPP-MGMT (match-any)
      6120044 packets, 734405280 bytes
      5 minute offered rate 9000 bps, drop rate 0000 bps
      Match: access-group name ACL-COPP-MGMT
      police:
          cir 1000000 bps, bc 31250 bytes
        conformed 6119980 packets, 734397600 bytes; actions:
          transmit
        exceeded 64 packets, 7680 bytes; actions:
          drop

    Class-map: COPP-ARP (match-any)
      2900340 packets, 185621760 bytes
      5 minute offered rate 4000 bps, drop rate 0000 bps
      Match: protocol arp
      police:
          cir 256000 bps, bc 8000 bytes
        conformed 2899011 packets, 185536704 bytes; actions:
          transmit
        exceeded 1329 packets, 85056 bytes; actions:
          drop

    Class-map: class-default (match-any)
      812004 packets, 97440480 bytes
      5 minute offered rate 1000 bps, drop rate 0000 bps
      Match: any
      police:
          cir 128000 bps, bc 4000 bytes
        conformed 811990 packets, 97438800 bytes; actions:
          transmit
        exceeded 14 packets, 1680 bytes; actions:
          drop
"""

# Five minutes later, during a loop on an access switch.
SNAPSHOT_2 = """\
 Control Plane

  Service-policy input: COPP-POLICY

    Class-map: COPP-ROUTING (match-any)
      18249950 packets, 1788495100 bytes
      5 minute offered rate 2101000 bps, drop rate 96000 bps
      Match: access-group name ACL-COPP-ROUTING
      police:
          cir 2000000 bps, bc 62500 bytes
        conformed 18249550 packets, 1788455900 bytes; actions:
          transmit
        exceeded 400 packets, 39200 bytes; actions:
          drop

    Class-map: COPP-MGMT (match-any)
      120 packets, 14400 bytes
      5 minute offered rate 8000 bps, drop rate 0000 bps
      Match: access-group name ACL-COPP-MGMT
      police:
          cir 1000000 bps, bc 31250 bytes
        conformed 120 packets, 14400 bytes; actions:
          transmit
        exceeded 0 packets, 0 bytes; actions:
          drop

    Class-map: COPP-ARP (match-any)
      3211040 packets, 205506560 bytes
      5 minute offered rate 530000 bps, drop rate 272000 bps
      Match: protocol arp
      police:
          cir 256000 bps, bc 8000 bytes
        conformed 2973011 packets, 190272704 bytes; actions:
          transmit
        exceeded 238029 packets, 15233856 bytes; actions:
          drop

    Class-map: class-default (match-any)
      812300 packets, 97476000 bytes
      5 minute offered rate 1000 bps, drop rate 0000 bps
      Match: any
      police:
          cir 128000 bps, bc 4000 bytes
        conformed 812286 packets, 97474320 bytes; actions:
          transmit
        exceeded 14 packets, 1680 bytes; actions:
          drop
"""

INTERVAL_S = 300
# Dropped packets per interval that are worth an alert, per class.
THRESHOLDS = {"COPP-ROUTING": 1, "COPP-MGMT": 100, "COPP-ARP": 10_000, "class-default": 1_000}
SEVERITY = {"COPP-ROUTING": "CRITICAL"}  # anything else is WARNING

CLASS_RE = re.compile(r"Class-map: (\S+)")
COUNT_RE = re.compile(r"(conformed|exceeded) (\d+) packets")


def parse(text: str) -> dict[str, dict[str, int]]:
    classes: dict[str, dict[str, int]] = {}
    current = None
    for line in text.splitlines():
        if m := CLASS_RE.search(line):
            current = m.group(1)
            classes[current] = {}
        elif current and (m := COUNT_RE.search(line)):
            classes[current][m.group(1)] = int(m.group(2))
    return classes


def main() -> None:
    before, after = parse(SNAPSHOT_1), parse(SNAPSHOT_2)
    print(f"{'class':<14} {'conform/s':>9} {'drop/s':>7} {'dropped':>8}  verdict")
    for name, now in after.items():
        old = before.get(name)
        if old is None or any(now[k] < old[k] for k in now):
            print(f"{name:<14} {'-':>9} {'-':>7} {'-':>8}  counters reset, skipped")
            continue
        conformed = now["conformed"] - old["conformed"]
        dropped = now["exceeded"] - old["exceeded"]
        if dropped >= THRESHOLDS.get(name, 1):
            verdict = SEVERITY.get(name, "WARNING")
        else:
            verdict = "ok"
        share = dropped / (conformed + dropped) * 100 if conformed + dropped else 0.0
        print(f"{name:<14} {conformed / INTERVAL_S:>9.1f} {dropped / INTERVAL_S:>7.1f} {dropped:>8}  "
              f"{verdict} ({share:.1f}% of offered)")


if __name__ == "__main__":
    main()

# Output:
# class          conform/s  drop/s  dropped  verdict
# COPP-ROUTING        53.8     1.3      400  CRITICAL (2.4% of offered)
# COPP-MGMT              -       -        -  counters reset, skipped
# COPP-ARP           246.7   789.0   236700  WARNING (76.2% of offered)
# class-default        1.0     0.0        0  ok (0.0% of offered)
