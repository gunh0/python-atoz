"""Colored severity output with ANSI escapes — and when not to emit them

Red CRIT, yellow WARN: on a terminal, color is how a long check report gets
read in two seconds. The same escape bytes are garbage in cron mail, in a
file, or in a ticket, so a tool should color only when it should:

- NO_COLOR set (https://no-color.org) -> never; FORCE_COLOR set -> always
- TERM=dumb -> never; otherwise only when the stream is a TTY

Two more traps. Padding a colored string with f"{s:<8}" counts the escape
bytes as characters and breaks column alignment, so pad first, color after.
And anything that stores the output (logs, diffs, tests) should strip the
codes with one regex for CSI sequences rather than ad hoc replace() calls.

The escapes are printed with repr() below so the output is plain text.
"""

import io
import re

RESET = "\x1b[0m"
STYLE = {
    "CRIT": "\x1b[1;31m",  # bold red
    "WARN": "\x1b[33m",    # yellow
    "OK": "\x1b[32m",      # green
    "INFO": "",            # default color
}
CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def should_color(stream, env: dict[str, str]) -> bool:
    if "NO_COLOR" in env:
        return False
    if "FORCE_COLOR" in env:
        return True
    if env.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def badge(level: str, color: bool, width: int = 5) -> str:
    text = f"{level:<{width}}"  # pad first, then color: alignment survives
    style = STYLE.get(level, "")
    return f"{style}{text}{RESET}" if color and style else text


def strip_ansi(text: str) -> str:
    return CSI.sub("", text)


class FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def main() -> None:
    cases = [
        ("tty, TERM=xterm-256color", FakeTTY(), {"TERM": "xterm-256color"}),
        ("tty, NO_COLOR=1", FakeTTY(), {"TERM": "xterm", "NO_COLOR": "1"}),
        ("tty, TERM=dumb", FakeTTY(), {"TERM": "dumb"}),
        ("pipe / cron mail", io.StringIO(), {"TERM": "xterm"}),
        ("pipe, FORCE_COLOR=1", io.StringIO(), {"FORCE_COLOR": "1"}),
    ]
    for label, stream, env in cases:
        print(f"{label:<26} color={should_color(stream, env)}")
    print()

    events = [("CRIT", "/srv/backup at 98%"), ("WARN", "load 9.5 on 4 CPUs"), ("OK", "ntp offset 3ms")]
    lines = [f"{badge(level, color=True)} {msg}" for level, msg in events]
    for line in lines:
        print(repr(line))
    print()
    print("stripped:")
    for line in lines:
        print(" ", strip_ansi(line))
    print()

    wrong = f"{STYLE['WARN'] + 'WARN' + RESET:<6}|"
    right = f"{badge('WARN', color=True, width=6)}|"
    print("padded after coloring:", repr(strip_ansi(wrong)))
    print("padded before coloring:", repr(strip_ansi(right)))
    print("cursor/erase codes stripped too:", repr(strip_ansi("\x1b[2K\x1b[1Gprogress 40%\x1b[?25h")))


if __name__ == "__main__":
    main()

# Output:
# tty, TERM=xterm-256color   color=True
# tty, NO_COLOR=1            color=False
# tty, TERM=dumb             color=False
# pipe / cron mail           color=False
# pipe, FORCE_COLOR=1        color=True
#
# '\x1b[1;31mCRIT \x1b[0m /srv/backup at 98%'
# '\x1b[33mWARN \x1b[0m load 9.5 on 4 CPUs'
# '\x1b[32mOK   \x1b[0m ntp offset 3ms'
#
# stripped:
#   CRIT  /srv/backup at 98%
#   WARN  load 9.5 on 4 CPUs
#   OK    ntp offset 3ms
#
# padded after coloring: 'WARN|'
# padded before coloring: 'WARN  |'
# cursor/erase codes stripped too: 'progress 40%'
