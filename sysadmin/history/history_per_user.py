"""Shell history per user: aggregate bash and zsh history files from one host

During an audit you collect every ~/.bash_history and ~/.zsh_history from a
host and want one table: who ran how much, when, and what. Three formats
show up in practice and a parser has to recognise each per file:

- bash without HISTTIMEFORMAT: one command per line, no time at all;
- bash with HISTTIMEFORMAT: "#<epoch>" line before each command;
- zsh with EXTENDED_HISTORY: ": <epoch>:<duration>;<command>".

The user comes from the path (/root or /home/<user>), not from the file
content. Times are shown in a fixed zone so the report does not depend on
the machine that renders it, and "no timestamps" is reported as such rather
than silently dropped from the time range.
"""

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9), "KST")

FILES = {
    "/root/.bash_history": """\
#1789340400
apt-get update
#1789340460
apt-get -y upgrade
#1789340900
systemctl restart sshd
#1789341000
vim /etc/ssh/sshd_config
#1789341100
systemctl restart sshd
""",
    "/home/alice/.zsh_history": """\
: 1789344131:0;kubectl get pods -n prod
: 1789344170:2;kubectl logs -n prod deploy/api --tail=200
: 1789344302:0;sudo journalctl -u kubelet -n 100
: 1789351200:0;kubectl get pods -n prod
: 1789351260:14;kubectl rollout restart -n prod deploy/api
: 1789351400:0;git -C ~/ops pull
""",
    "/home/bob/.bash_history": """\
ls
cd /var/www
sudo -u www-data php artisan cache:clear
tail -f storage/logs/laravel.log
sudo systemctl reload php8.3-fpm
ls
""",
    "/home/svc-backup/.bash_history": "",
}

ZSH_LINE = re.compile(r"^: (\d+):(\d+);(.*)$")


@dataclass
class UserHistory:
    user: str
    fmt: str = "empty"
    commands: list[str] = field(default_factory=list)
    times: list[datetime] = field(default_factory=list)


def user_from_path(path: str) -> str:
    parts = path.strip("/").split("/")
    return "root" if parts[0] == "root" else parts[1]


def parse_file(path: str, text: str) -> UserHistory:
    h = UserHistory(user_from_path(path))
    lines = text.splitlines()
    if not lines:
        return h
    if ZSH_LINE.match(lines[0]):
        h.fmt = "zsh extended"
        for line in lines:
            if m := ZSH_LINE.match(line):
                h.times.append(datetime.fromtimestamp(int(m.group(1)), KST))
                h.commands.append(m.group(3))
    elif lines[0].startswith("#") and lines[0][1:].isdigit():
        h.fmt = "bash timestamped"
        for line in lines:
            if line.startswith("#") and line[1:].isdigit():
                h.times.append(datetime.fromtimestamp(int(line[1:]), KST))
            else:
                h.commands.append(line)
    else:
        h.fmt = "bash plain"
        h.commands = lines
    return h


def program(command: str) -> str:
    words = command.split()
    while words and words[0] == "sudo":
        words = words[1:]
        while words and words[0].startswith("-"):  # sudo -u www-data ...
            words = words[2:] if words[0] in ("-u", "-g") else words[1:]
    return words[0] if words else ""


def main() -> None:
    users = [parse_file(path, text) for path, text in FILES.items()]
    print(f"{'user':<11} {'format':<17} {'cmds':>4}  {'sudo':>4}  time range (KST)")
    for h in users:
        sudo = sum(c.startswith("sudo ") for c in h.commands)
        if h.times:
            span = f"{min(h.times):%m-%d %H:%M} .. {max(h.times):%m-%d %H:%M}"
        else:
            span = "no timestamps" if h.commands else "-"
        print(f"{h.user:<11} {h.fmt:<17} {len(h.commands):>4}  {sudo:>4}  {span}")

    print()
    for h in users:
        if h.commands:
            top = Counter(program(c) for c in h.commands).most_common(3)
            print(f"{h.user:<11} top: " + ", ".join(f"{name} x{n}" for name, n in top))

    print()
    owners: dict[str, set[str]] = {}
    for h in users:
        for c in h.commands:
            owners.setdefault(program(c), set()).add(h.user)
    print("service/package tools and who used them:")
    privileged = sorted(p for p in ("systemctl", "journalctl", "apt-get") if p in owners)
    for name in privileged:
        print(f"  {name:<11} run by: {', '.join(sorted(owners[name]))}")


if __name__ == "__main__":
    main()

# Output:
# user        format            cmds  sudo  time range (KST)
# root        bash timestamped     5     0  09-14 08:00 .. 09-14 08:11
# alice       zsh extended         6     1  09-14 09:02 .. 09-14 11:03
# bob         bash plain           6     2  no timestamps
# svc-backup  empty                0     0  -
#
# root        top: apt-get x2, systemctl x2, vim x1
# alice       top: kubectl x4, journalctl x1, git x1
# bob         top: ls x2, cd x1, php x1
#
# service/package tools and who used them:
#   apt-get     run by: root
#   journalctl  run by: alice
#   systemctl   run by: bob, root
