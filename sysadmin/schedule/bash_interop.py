"""Bash <-> Python interop for cron scripts — exit codes and pipes both ways

Cron jobs are usually a Bash wrapper around a Python check, or a Python
job that shells out to existing Bash. The contract between them is small:
bytes on stdin/stdout and an exit status from 0 to 255. Get those right and
the two compose; get them wrong and failures vanish silently.

- Python as a filter in a pipeline: read sys.stdin, write sys.stdout, and
  report through the exit code (here the Nagios convention 0 OK, 1 WARN,
  2 CRIT). In Bash, `set -o pipefail` or ${PIPESTATUS[@]} is needed to see
  a failure that happens before the last stage of a pipe.
- Exit statuses are taken modulo 256: sys.exit(256) is success to the shell.
- Python feeding Bash: pass data on stdin or in environment variables, never
  by pasting it into the script text, so a filename like "a b; rm x" stays
  data. Popen chains need p1.stdout.close() so p1 learns when p2 has exited.
"""

import subprocess
import sys

PY = sys.executable

DISK_FILTER = r"""
import sys
worst = 0
for line in sys.stdin:
    mount, pct = line.split()
    pct = int(pct.rstrip("%"))
    level = 2 if pct >= 95 else 1 if pct >= 85 else 0
    worst = max(worst, level)
    if level:
        print(("WARN", "CRIT")[level - 1], mount, f"{pct}%")
sys.exit(worst)
"""

WRAPPER = r"""
report() {
    printf '/ 61%%\n/var 88%%\n/srv/backup %s\n' "$1" | "$PY" -c "$FILTER"
}
for backup in 40% 97%; do
    out=$(report "$backup"); rc=$?
    case $rc in
        0) echo "backup=$backup -> OK" ;;
        1) echo "backup=$backup -> WARN, mail the team: $out" ;;
        2) echo "backup=$backup -> CRIT, page on-call: $(echo "$out" | paste -s -d ';' -)" ;;
    esac
done

"$PY" -c 'import sys; sys.exit(3)' | cat; echo "without pipefail: \$?=$? PIPESTATUS=${PIPESTATUS[*]}"
set -o pipefail
"$PY" -c 'import sys; sys.exit(3)' | cat; echo "with pipefail:    \$?=$?"
"$PY" -c 'import sys; sys.exit(256)'; echo "sys.exit(256) seen by bash: $?"
"""


def main() -> None:
    env = {"PATH": "/usr/bin:/bin", "PY": PY, "FILTER": DISK_FILTER}
    proc = subprocess.run(["bash", "-c", WRAPPER], capture_output=True, text=True, env=env)
    print("[bash wrapper calling the Python filter]")
    print(proc.stdout, end="")
    print()

    print("[Python calling bash, data via env and stdin]")
    hostile = "logs/a b; rm -rf x"
    script = 'printf "file=[%s]\\n" "$TARGET"; while read -r host; do echo "ping $host"; done'
    proc = subprocess.run(["bash", "-c", script], input="web-01\ndb-01\n", capture_output=True,
                          text=True, env={"PATH": "/usr/bin:/bin", "TARGET": hostile})
    print(proc.stdout, end="")
    print("returncode:", proc.returncode)
    print()

    print("[Popen chain: producer | head -n 2]")
    producer = subprocess.Popen([PY, "-c", "import sys\nfor i in range(100000): print('line', i)"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    head = subprocess.Popen(["head", "-n", "2"], stdin=producer.stdout, stdout=subprocess.PIPE, text=True)
    producer.stdout.close()  # only head holds the read end now, so the producer
    # sees a broken pipe when head exits (SIGPIPE for C tools, BrokenPipeError in Python)
    out, _ = head.communicate()
    producer.wait()
    print(out, end="")
    print(f"head exit {head.returncode}; producer stopped early: {producer.returncode != 0}")


if __name__ == "__main__":
    main()

# Output:
# [bash wrapper calling the Python filter]
# backup=40% -> WARN, mail the team: WARN /var 88%
# backup=97% -> CRIT, page on-call: WARN /var 88%;CRIT /srv/backup 97%
# without pipefail: $?=0 PIPESTATUS=3 0
# with pipefail:    $?=3
# sys.exit(256) seen by bash: 0
#
# [Python calling bash, data via env and stdin]
# file=[logs/a b; rm -rf x]
# ping web-01
# ping db-01
# returncode: 0
#
# [Popen chain: producer | head -n 2]
# line 0
# line 1
# head exit 0; producer stopped early: True
