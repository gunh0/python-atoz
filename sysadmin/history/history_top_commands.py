"""Shell history: which commands does this account actually run?

Before automating anything on a server it pays to look at what people type
there. ~/.bash_history is one command line per entry, so the obvious
`cut -d' ' -f1 | sort | uniq -c` gets you most of the way, but it counts
`sudo`, `time` and `env FOO=1` as "the command" and treats a pipeline as one
thing. Here each line is split with shlex, wrappers are peeled off, and every
stage of a pipeline or `&&` chain is counted on its own.

shlex is strict about quotes; a history line with an unbalanced quote (a
half-typed command the user aborted) raises ValueError, and we fall back to a
plain whitespace split instead of dropping the line.
"""

import shlex
from collections import Counter

BASH_HISTORY = """\
ls -la
cd /var/log
sudo tail -f syslog
grep -i error syslog | less
df -h
du -sh /var/lib/* | sort -h
systemctl status nginx
sudo systemctl restart nginx
journalctl -u nginx --since "10 min ago"
ls
cd ~
vim /etc/nginx/sites-available/default
sudo nginx -t && sudo systemctl reload nginx
df -h
free -m
time tar czf /tmp/etc.tgz /etc
ps aux | grep nginx
ss -tlnp
ls -la /etc/nginx
env LANG=C sort access.log | uniq -c | sort -rn | head
git -C /srv/app pull
sudo systemctl restart app
journalctl -u app -n 50
echo "it's broken
df -h
history | tail
"""

WRAPPERS = {"sudo", "time", "nohup", "nice", "env", "command"}
SEPARATORS = {"|", "||", "&&", ";"}


def tokens(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True, punctuation_chars="|&;")
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes
        return line.split()


def commands_in(line: str) -> list[str]:
    """Return the program name of every stage in a command line."""
    found, expect_command = [], True
    for tok in tokens(line):
        if tok in SEPARATORS:
            expect_command = True
        elif expect_command:
            if tok in WRAPPERS or ("=" in tok and not tok.startswith("=")):
                continue  # sudo/time/env, or VAR=value before the command
            if tok.startswith("-"):
                continue  # option of a wrapper, e.g. `nice -n 10`
            found.append(tok.rsplit("/", 1)[-1])
            expect_command = False
    return found


def main() -> None:
    lines = BASH_HISTORY.splitlines()
    naive = Counter(line.split()[0] for line in lines if line.strip())
    smart = Counter(cmd for line in lines for cmd in commands_in(line))

    print(f"{len(lines)} history lines, {sum(smart.values())} commands")
    print()
    print("naive first word       peeled + split")
    left = naive.most_common(8)
    right = smart.most_common(8)
    for (n_cmd, n_cnt), (s_cmd, s_cnt) in zip(left, right):
        print(f"  {n_cnt:>2} {n_cmd:<16}    {s_cnt:>2} {s_cmd}")
    print()
    print("sudo lines:", sum(1 for line in lines if line.startswith("sudo ")))
    print("pipelines: ", sum(1 for line in lines if "|" in tokens(line)))


if __name__ == "__main__":
    main()

# Output:
# 26 history lines, 34 commands
#
# naive first word       peeled + split
#    4 sudo                 4 systemctl
#    3 ls                   3 ls
#    3 df                   3 df
#    2 cd                   3 sort
#    2 journalctl           2 cd
#    1 grep                 2 tail
#    1 du                   2 grep
#    1 systemctl            2 journalctl
#
# sudo lines: 4
# pipelines:  5
