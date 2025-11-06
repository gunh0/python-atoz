# requires-python: >=3.14
"""CWE-79 / CWE-78 with PEP 750 template strings: render HTML and argv safely

https://cwe.mitre.org/data/definitions/79.html   (https://cwe.mitre.org/data/definitions/78.html)

Follow-up to tstring_safe_sql: the same trick works for any language where
data must not become syntax. html() escapes every interpolated value with
html.escape(), refuses values in unquoted attributes and checks the scheme
of values that start an href/src (cwe79_*), and lets nested t-strings
through as already-safe markup, so components compose without
double-escaping. argv() never builds a command line at all: literal text is
split on whitespace, and each interpolation becomes part of exactly one
argv element (a list value becomes several), which subprocess runs without
a shell (cwe78_*). "--" is still yours to write (cwe88).

The renderer decides context from the literal text before each value, which
is what makes t-strings better than f-strings plus "remember to escape".
These helpers are deliberately small; real template engines track context
far more precisely.
"""

import html as _html
import subprocess
from string.templatelib import Template
from urllib.parse import urlsplit

URL_ATTRS = ('href="', 'src="', "href='", "src='")


def html(tmpl: Template) -> str:
    if not isinstance(tmpl, Template):
        raise TypeError("html() takes a t-string")
    out: list[str] = []
    for part in tmpl:
        if isinstance(part, str):
            out.append(part)
            continue
        value = part.value
        if isinstance(value, Template):
            out.append(html(value))
            continue
        before = "".join(out)
        if before.endswith("="):
            raise ValueError(f"{{{part.expression}}} in an unquoted attribute")
        text = str(value)
        if before.endswith(URL_ATTRS) and urlsplit(text).scheme not in ("", "http", "https"):
            text = "#blocked"
        out.append(_html.escape(text))
    return "".join(out)


def argv(tmpl: Template) -> list[str]:
    if not isinstance(tmpl, Template):
        raise TypeError("argv() takes a t-string")
    args: list[str] = []
    cur: str | None = None
    for part in tmpl:
        if isinstance(part, str):
            words = part.split()
            if part[:1].isspace() and cur is not None:
                args.append(cur)
                cur = None
            for i, word in enumerate(words):
                if i == 0 and cur is not None:
                    cur += word
                else:
                    if cur is not None:
                        args.append(cur)
                    cur = word
            if part[-1:].isspace() and cur is not None:
                args.append(cur)
                cur = None
        elif isinstance(part.value, (list, tuple)):
            if cur is not None:
                raise ValueError(f"list {{{part.expression}}} glued to other text")
            args.extend(str(v) for v in part.value)
        else:
            cur = (cur or "") + str(part.value)
    if cur is not None:
        args.append(cur)
    return args


def show_argv(args: list[str]) -> str:
    """Run printf so the output shows exactly where each argument starts and ends."""
    proc = subprocess.run(["printf", "[%s] ", *args[1:]], capture_output=True, text=True)
    return f"{args[0]} {proc.stdout.strip()}"


def main() -> None:
    name = '<script>alert(1)</script>'
    link = "javascript:alert(document.cookie)"
    title = '" onmouseover="alert(1)'
    badge = t"<b>{'admin'}</b>"
    print("noncompliant f-string html:")
    print(" ", f'<a href="{link}" title="{title}">{name}</a>')
    print("compliant t-string html:")
    print(" ", html(t'<a href="{link}" title="{title}">{name}</a> {badge}'))
    try:
        html(t"<input value={title}>")
    except ValueError as exc:
        print("  refused:", exc)
    print()

    filename = "report.txt; echo INJECTED"
    flags = ["-n", "5"]
    print("noncompliant f-string shell:")
    proc = subprocess.run(f"echo head {filename}", shell=True, capture_output=True, text=True)
    print("  sh output lines:", proc.stdout.splitlines())
    print("compliant t-string argv:")
    print(" ", show_argv(argv(t"head {flags} -- {filename}")))
    print(" ", show_argv(argv(t"tar --file={filename} -x")))
    print(" ", show_argv(argv(t"grep -e {'-v'} -- {'two words'} log.txt")))


if __name__ == "__main__":
    main()

# Output:
# noncompliant f-string html:
#   <a href="javascript:alert(document.cookie)" title="" onmouseover="alert(1)"><script>alert(1)</script></a>
# compliant t-string html:
#   <a href="#blocked" title="&quot; onmouseover=&quot;alert(1)">&lt;script&gt;alert(1)&lt;/script&gt;</a> <b>admin</b>
#   refused: {title} in an unquoted attribute
#
# noncompliant f-string shell:
#   sh output lines: ['head report.txt', 'INJECTED']
# compliant t-string argv:
#   head [-n] [5] [--] [report.txt; echo INJECTED]
#   tar [--file=report.txt; echo INJECTED] [-x]
#   grep [-e] [-v] [--] [two words] [log.txt]
