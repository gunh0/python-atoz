r"""CWE-601: open redirect — "?next=" must stay on your own site

https://cwe.mitre.org/data/definitions/601.html

After login the app sends a 302 to request.args["next"]. Unchecked, a phishing
mail links to https://app.example/login?next=https://evil.example/login and
the user lands on a copy of the login page from a URL that started at the
real one. OAuth flows turn the same bug into token theft.

"Must start with /" is the usual check and browsers defeat it: //evil.example
is protocol-relative, /\evil.example and ///evil.example are read as
//evil.example because browsers treat "\" as "/" and collapse extra slashes,
and tabs or newlines are silently removed. urlsplit() agrees with none of
that, so "no netloc" is not a check either. Accept only a single leading "/"
followed by a non-slash, reject backslashes and control characters, or
better, map next= to known routes. The "browser" column models the WHATWG
URL rules for these inputs.
"""

import re
from urllib.parse import urlsplit

OWN_HOST = "app.example"
TARGETS = [
    "/dashboard",
    "/settings?tab=keys",
    "https://evil.example/login",
    "//evil.example/login",
    "/\\evil.example/login",
    "///evil.example/login",
    "/\t/evil.example/login",
    " //evil.example/login",
    "https:evil.example",
    "javascript:alert(1)",
]


def browser_destination(location: str) -> str:
    """Where a browser goes for Location: <location> on https://app.example/login."""
    s = location.strip("".join(map(chr, range(0x21))))
    s = re.sub(r"[\t\n\r]", "", s).replace("\\", "/")
    m = re.match(r"([A-Za-z][A-Za-z0-9+.\-]*):(.*)", s)
    if m:
        scheme, rest = m.group(1).lower(), m.group(2)
        if scheme not in ("http", "https"):
            return f"{scheme}: URL"
        s = rest                                    # https:evil.example == https://evil.example
        if not s.startswith("/"):
            return s.split("/")[0]
    m = re.match(r"/{2,}([^/?#]*)", s)
    return m.group(1) if m else OWN_HOST


def noncompliant_raw(target: str) -> str:
    return target


def noncompliant_startswith(target: str) -> str:
    return target if target.startswith("/") else "/"


def noncompliant_no_netloc(target: str) -> str:
    parts = urlsplit(target)
    return target if not parts.scheme and not parts.netloc else "/"


SAFE_PATH = re.compile(r"/(?![/\\])[A-Za-z0-9/._~\-?=&%]*")


def compliant(target: str) -> str:
    return target if SAFE_PATH.fullmatch(target) else "/"


def main() -> None:
    fns = (noncompliant_raw, noncompliant_startswith, noncompliant_no_netloc, compliant)
    print(f"{'next=':30}" + "".join(f"{fn.__name__.replace('noncompliant_', 'nc_'):>17}" for fn in fns))
    for target in TARGETS:
        cells = "".join(f"{browser_destination(fn(target)):>17}" for fn in fns)
        print(f"{target!r:30}{cells}")


if __name__ == "__main__":
    main()

# Output:
# next=                                    nc_raw    nc_startswith     nc_no_netloc        compliant
# '/dashboard'                        app.example      app.example      app.example      app.example
# '/settings?tab=keys'                app.example      app.example      app.example      app.example
# 'https://evil.example/login'       evil.example      app.example      app.example      app.example
# '//evil.example/login'             evil.example     evil.example      app.example      app.example
# '/\\evil.example/login'            evil.example     evil.example     evil.example      app.example
# '///evil.example/login'            evil.example     evil.example     evil.example      app.example
# '/\t/evil.example/login'           evil.example     evil.example      app.example      app.example
# ' //evil.example/login'            evil.example      app.example      app.example      app.example
# 'https:evil.example'               evil.example      app.example      app.example      app.example
# 'javascript:alert(1)'           javascript: URL      app.example      app.example      app.example
