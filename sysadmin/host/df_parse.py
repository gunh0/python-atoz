"""Parsing `df -h` — wrapped lines, human sizes and mount points with spaces

`df -h | awk '{print $5}'` works until it does not. Three things break it on
real servers: a long device name (LVM, NFS export) makes older df print the
remaining columns on the next line; a mount point containing a space shifts
every awk field after it; and "1.8T" vs "512M" cannot be compared as text.

The parser below joins a wrapped line with its continuation, splits only the
first five fields so the rest of the line is the mount point, converts sizes
to bytes, and skips pseudo filesystems (tmpfs, overlay, devtmpfs) that make
a disk report noisy. In scripts prefer `df -P -k`, whose output never wraps
and has exact numbers; this example shows how to cope with the -h output
you are given in a ticket or old cron mail.
"""

DF_H_SAMPLE = """\
Filesystem                          Size  Used Avail Use% Mounted on
udev                                7.8G     0  7.8G   0% /dev
tmpfs                               1.6G  2.1M  1.6G   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv
                                     98G   81G   13G  87% /
tmpfs                               7.8G     0  7.8G   0% /dev/shm
/dev/nvme0n1p2                      2.0G  251M  1.6G  14% /boot
/dev/sdb1                           1.8T  1.7T   45G  98% /srv/backup
nas01:/export/home                  500G  120G  380G  24% /mnt/team share
overlay                              98G   81G   13G  87% /var/lib/docker/overlay2/3f9c/merged
"""

PSEUDO = {"tmpfs", "devtmpfs", "udev", "overlay", "squashfs"}
UNITS = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4, "P": 1024**5}


def to_bytes(size: str) -> int:
    """'1.8T' -> bytes. df -h uses powers of 1024; a bare number is bytes."""
    if size[-1] in UNITS:
        return round(float(size[:-1]) * UNITS[size[-1]])
    return int(size)


def logical_lines(text: str) -> list[str]:
    """Join a device-only line with the indented line that continues it."""
    out = []
    for line in text.splitlines()[1:]:  # skip header
        if line.startswith((" ", "\t")) and out:
            out[-1] = out[-1] + " " + line.strip()
        elif line.strip():
            out.append(line)
    return out


def parse_df(text: str) -> list[dict]:
    rows = []
    for line in logical_lines(text):
        device, size, used, avail, pct, mount = line.split(maxsplit=5)
        rows.append({
            "device": device,
            "size": to_bytes(size),
            "used": to_bytes(used),
            "avail": to_bytes(avail),
            "use_pct": int(pct.rstrip("%")),
            "mount": mount,
        })
    return rows


def is_real(row: dict) -> bool:
    return row["device"] not in PSEUDO and not row["mount"].startswith("/var/lib/docker/")


def main() -> None:
    rows = parse_df(DF_H_SAMPLE)
    print(f"parsed {len(rows)} filesystems, {sum(map(is_real, rows))} real")
    print()
    for row in sorted(filter(is_real, rows), key=lambda r: r["use_pct"], reverse=True):
        level = "CRIT" if row["use_pct"] >= 95 else "WARN" if row["use_pct"] >= 85 else "ok"
        free_gib = row["avail"] / 1024**3
        print(f"{level:<4} {row['use_pct']:>3}%  {free_gib:>7.1f} GiB free  {row['mount']!r:<17} {row['device']}")
    print()
    backup = next(r for r in rows if r["mount"] == "/srv/backup")
    print("bytes used on /srv/backup:", backup["used"])
    nas_line = next(line for line in logical_lines(DF_H_SAMPLE) if line.startswith("nas01:"))
    print("naive awk $6 on the NAS line gives:", repr(nas_line.split()[5]))


if __name__ == "__main__":
    main()

# Output:
# parsed 8 filesystems, 4 real
#
# CRIT  98%     45.0 GiB free  '/srv/backup'     /dev/sdb1
# WARN  87%     13.0 GiB free  '/'               /dev/mapper/ubuntu--vg-ubuntu--lv
# ok    24%    380.0 GiB free  '/mnt/team share' nas01:/export/home
# ok    14%      1.6 GiB free  '/boot'           /dev/nvme0n1p2
#
# bytes used on /srv/backup: 1869169767219
# naive awk $6 on the NAS line gives: '/mnt/team'
