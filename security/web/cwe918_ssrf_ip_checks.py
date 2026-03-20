"""CWE-918: SSRF — check the address you will connect to, not the string you got

https://cwe.mitre.org/data/definitions/918.html

"Fetch this URL for a preview" endpoints get pointed at 127.0.0.1:6379,
10.x admin panels and the cloud metadata service at 169.254.169.254. String
blocklists miss the many spellings the C resolver accepts: inet_aton() reads
2130706433, 0x7f.1, 127.1 and 0177.0.0.1 as 127.0.0.1. ipaddress rejects
those spellings, so "not an IP, must be a hostname, allow it" is a bypass too.
IPv6 adds ::ffff:127.0.0.1 (IPv4-mapped) and 64:ff9b::/96 (NAT64), which
ipaddress reports as global.

Turn the host into the address the client will actually use, unwrap mapped,
NAT64 and 6to4 addresses, and require is_global (is_private alone misses
100.64.0.0/10 and others). In production resolve once with getaddrinfo, check
every result, then connect to that checked IP so DNS cannot change its answer
in between. This demo stays offline: it uses inet_aton because getaddrinfo
disagrees across platforms (macOS reads 0177.0.0.1 as 177.0.0.1).
"""

import ipaddress
import socket
from urllib.parse import urlsplit

NAT64 = ipaddress.ip_network("64:ff9b::/96")
URLS = [
    "http://93.184.215.14/",
    "http://127.0.0.1:6379/",
    "http://2130706433/",
    "http://0x7f.1/",
    "http://127.1/",
    "http://0177.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:169.254.169.254]/",
    "http://[::ffff:7f00:1]/",
    "http://[64:ff9b::a9fe:a9fe]/",
    "http://[2002:a9fe:a9fe::]/",
    "http://100.64.0.1/",
    "http://[fe80::1]/",
    "http://0.0.0.0:8080/",
]


def connects_to(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """What a C-library client ends up dialling for a numeric host."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(host)))


def noncompliant_blocklist(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    return not (host in {"localhost", "0.0.0.0", "169.254.169.254"}
                or host.startswith(("127.", "10.", "192.168.", "172.16.")))


def noncompliant_is_private(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return True                      # "a hostname, not an IP": allowed
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def unwrap(addr):
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            return addr.ipv4_mapped
        if addr in NAT64:
            return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        if addr.sixtofour:
            return addr.sixtofour
    return addr


def compliant(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        addr = unwrap(connects_to(parts.hostname))
    except (OSError, ValueError):
        return False
    return addr.is_global and not addr.is_multicast


def main() -> None:
    print(f"{'url':42}{'dials':24}{'blocklist':11}{'is_private':12}compliant")
    for url in URLS:
        dials = str(connects_to(urlsplit(url).hostname))
        verdicts = [("allow" if fn(url) else "block") for fn in
                    (noncompliant_blocklist, noncompliant_is_private, compliant)]
        print(f"{url:42}{dials:24}{verdicts[0]:11}{verdicts[1]:12}{verdicts[2]}")


if __name__ == "__main__":
    main()

# Output:
# url                                       dials                   blocklist  is_private  compliant
# http://93.184.215.14/                     93.184.215.14           allow      allow       allow
# http://127.0.0.1:6379/                    127.0.0.1               block      block       block
# http://2130706433/                        127.0.0.1               allow      allow       block
# http://0x7f.1/                            127.0.0.1               allow      allow       block
# http://127.1/                             127.0.0.1               block      allow       block
# http://0177.0.0.1/                        127.0.0.1               allow      allow       block
# http://169.254.169.254/latest/meta-data/  169.254.169.254         block      block       block
# http://[::ffff:169.254.169.254]/          ::ffff:169.254.169.254  allow      block       block
# http://[::ffff:7f00:1]/                   ::ffff:127.0.0.1        allow      block       block
# http://[64:ff9b::a9fe:a9fe]/              64:ff9b::a9fe:a9fe      allow      allow       block
# http://[2002:a9fe:a9fe::]/                2002:a9fe:a9fe::        allow      block       block
# http://100.64.0.1/                        100.64.0.1              allow      allow       block
# http://[fe80::1]/                         fe80::1                 allow      block       block
# http://0.0.0.0:8080/                      0.0.0.0                 block      block       block
