"""System inventory with platform, os and shutil — collect live, report from data

The first script most admins write is "tell me what this box is": OS, kernel,
CPU count, disk size, which tools are installed. The standard library already
has all of it: platform.uname(), os.cpu_count(), shutil.disk_usage() and
shutil.which(). The mistake is to print those values straight away and grep
the text later. Collect them into a plain dict first, so the same record can
be validated, diffed against yesterday's, or merged into a fleet table.

Here the live collector runs on this machine, but only machine-independent
checks about it are printed (the values themselves differ per host). The
fleet report is computed from records collected earlier, embedded below,
together with an /etc/os-release sample parsed the way platform does it.
"""

import os
import platform
import shlex
import shutil

OS_RELEASE_SAMPLE = """\
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
# comments and blank lines are allowed

HOME_URL="https://www.ubuntu.com/"
"""

# Records produced by collect() on three servers last week.
FLEET = [
    {"hostname": "web-01", "system": "Linux", "release": "6.8.0-45-generic", "machine": "x86_64",
     "cpus": 8, "disk_total": 107_374_182_400, "disk_used": 41_875_931_136,
     "tools": {"ssh": True, "rsync": True, "tcpdump": False}},
    {"hostname": "db-01", "system": "Linux", "release": "6.8.0-45-generic", "machine": "x86_64",
     "cpus": 32, "disk_total": 1_099_511_627_776, "disk_used": 989_560_464_998,
     "tools": {"ssh": True, "rsync": True, "tcpdump": True}},
    {"hostname": "build-mac", "system": "Darwin", "release": "24.6.0", "machine": "arm64",
     "cpus": 10, "disk_total": 494_384_795_648, "disk_used": 212_585_463_808,
     "tools": {"ssh": True, "rsync": True, "tcpdump": True}},
]

TOOLS = ("ssh", "rsync", "tcpdump")


def collect(root: str = "/") -> dict:
    """Gather one host record. Every value is plain data (str/int/bool)."""
    uname = platform.uname()
    usage = shutil.disk_usage(root)
    return {
        "hostname": uname.node,
        "system": uname.system,
        "release": uname.release,
        "machine": uname.machine,
        "cpus": os.cpu_count() or 1,
        "disk_total": usage.total,
        "disk_used": usage.used,
        "tools": {name: shutil.which(name) is not None for name in TOOLS},
    }


def parse_os_release(text: str) -> dict[str, str]:
    """Parse os-release(5): KEY=value lines, values may be shell-quoted."""
    info = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        parts = shlex.split(value)  # removes quotes and handles escapes
        info[key] = parts[0] if parts else ""
    return info


def human(n: int) -> str:
    """Bytes to a short binary-unit string, like df -h."""
    size = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if size < 1024 or unit == "T":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    raise AssertionError("unreachable")


def validate(record: dict) -> list[str]:
    """Return problems with a record; an empty list means it is usable."""
    problems = []
    for key in ("hostname", "system", "release", "machine"):
        if not isinstance(record.get(key), str):
            problems.append(f"{key} is not a string")
    if not isinstance(record.get("cpus"), int) or record["cpus"] < 1:
        problems.append("cpus must be a positive int")
    if not 0 <= record.get("disk_used", -1) <= record.get("disk_total", -1):
        problems.append("disk_used must be between 0 and disk_total")
    return problems


def main() -> None:
    live = collect()
    print("live record keys:", ", ".join(sorted(live)))
    print("live record valid:", validate(live) == [])
    print("python implementation:", platform.python_implementation())
    print("sh found on PATH:", shutil.which("sh") is not None)
    print()

    release = parse_os_release(OS_RELEASE_SAMPLE)
    print(f"os-release: {release['PRETTY_NAME']} (id={release['ID']}, like={release['ID_LIKE']})")
    print()

    print(f"{'host':<10} {'os':<32} {'cpus':>4} {'disk':>7} {'used':>5}  missing tools")
    for rec in FLEET:
        pct = rec["disk_used"] / rec["disk_total"] * 100
        missing = [t for t, ok in rec["tools"].items() if not ok] or ["-"]
        os_name = f"{rec['system']} {rec['release']} {rec['machine']}"
        print(f"{rec['hostname']:<10} {os_name:<32} {rec['cpus']:>4} {human(rec['disk_total']):>7} "
              f"{pct:>4.0f}%  {', '.join(missing)}")
    print()
    print("total cpus:", sum(r["cpus"] for r in FLEET))
    kernels = sorted({(r["system"], r["release"]) for r in FLEET})
    print("distinct kernels:", "; ".join(f"{s} {r}" for s, r in kernels))
    full = [r["hostname"] for r in FLEET if r["disk_used"] / r["disk_total"] >= 0.85]
    print("disks at or above 85%:", ", ".join(full) or "none")


if __name__ == "__main__":
    main()

# Output:
# live record keys: cpus, disk_total, disk_used, hostname, machine, release, system, tools
# live record valid: True
# python implementation: CPython
# sh found on PATH: True
#
# os-release: Ubuntu 24.04.1 LTS (id=ubuntu, like=debian)
#
# host       os                               cpus    disk  used  missing tools
# web-01     Linux 6.8.0-45-generic x86_64       8  100.0G   39%  tcpdump
# db-01      Linux 6.8.0-45-generic x86_64      32    1.0T   90%  -
# build-mac  Darwin 24.6.0 arm64                10  460.4G   43%  -
#
# total cpus: 50
# distinct kernels: Darwin 24.6.0; Linux 6.8.0-45-generic
# disks at or above 85%: db-01
