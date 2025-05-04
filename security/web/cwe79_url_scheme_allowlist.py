"""CWE-79: user-supplied links — escaping is not enough inside href

https://cwe.mitre.org/data/definitions/79.html

A profile "website" field rendered as <a href="..."> can be perfectly
HTML-escaped and still run script: javascript:alert(1) contains nothing that
html.escape() changes. Blocklisting "javascript:" fails too, because browsers
are lenient: they ignore case, strip leading spaces and control characters,
delete tabs and newlines anywhere in the URL, and decode entities such as
&colon; in attribute values before looking at the scheme.

Parse the URL with urllib.parse.urlsplit (which applies the same stripping
since the CVE-2023-24329 fix), allow only the schemes you need, and then
escape the attribute with html.escape(). The "browser" column below decodes
the attribute the way an HTML tokenizer does and applies the WHATWG URL
cleanup to find the scheme that would actually run.
"""

import html
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https", "mailto"}
LINKS = [
    "https://ada.example/blog",
    "/users/ada",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    " \tjava\nscript:alert(1)",
    "\x01javascript:alert(1)",
    "javascript&colon;alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
]


class Href(HTMLParser):
    def handle_starttag(self, tag, attrs):
        self.href = dict(attrs).get("href")  # HTMLParser unescapes entities like a browser


def browser_scheme(markup: str) -> str:
    if markup.startswith("<span"):
        return "blocked"
    p = Href()
    p.feed(markup)
    url = p.href.strip("".join(map(chr, range(0x21))))   # C0 controls and space
    url = re.sub(r"[\t\n\r]", "", url)
    m = re.match(r"([A-Za-z][A-Za-z0-9+.\-]*):", url)
    scheme = m.group(1).lower() if m else "(relative)"
    return f"{scheme:12} {'SCRIPT SCHEME' if scheme in ('javascript', 'vbscript', 'data') else 'ok'}"


def noncompliant_blocklist(url: str) -> str:
    if url.lower().startswith("javascript:"):
        return "<span>blocked</span>"
    return f'<a href="{html.escape(url)}">site</a>'


def noncompliant_unescaped(url: str) -> str:
    if urlsplit(url).scheme not in ALLOWED_SCHEMES | {""}:
        return "<span>blocked</span>"
    return f'<a href="{url}">site</a>'  # forgot html.escape: &colon; is decoded later


def compliant(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES and not (parts.scheme == "" and url.startswith("/")):
        return "<span>blocked</span>"
    return f'<a href="{html.escape(url)}">site</a>'


def main() -> None:
    for url in LINKS:
        print(f"link {url!r}")
        for fn in (noncompliant_blocklist, noncompliant_unescaped, compliant):
            print(f"  {fn.__name__:23} {browser_scheme(fn(url))}")


if __name__ == "__main__":
    main()

# Output:
# link 'https://ada.example/blog'
#   noncompliant_blocklist  https        ok
#   noncompliant_unescaped  https        ok
#   compliant               https        ok
# link '/users/ada'
#   noncompliant_blocklist  (relative)   ok
#   noncompliant_unescaped  (relative)   ok
#   compliant               (relative)   ok
# link 'javascript:alert(1)'
#   noncompliant_blocklist  blocked
#   noncompliant_unescaped  blocked
#   compliant               blocked
# link 'JaVaScRiPt:alert(1)'
#   noncompliant_blocklist  blocked
#   noncompliant_unescaped  blocked
#   compliant               blocked
# link ' \tjava\nscript:alert(1)'
#   noncompliant_blocklist  javascript   SCRIPT SCHEME
#   noncompliant_unescaped  blocked
#   compliant               blocked
# link '\x01javascript:alert(1)'
#   noncompliant_blocklist  javascript   SCRIPT SCHEME
#   noncompliant_unescaped  blocked
#   compliant               blocked
# link 'javascript&colon;alert(1)'
#   noncompliant_blocklist  (relative)   ok
#   noncompliant_unescaped  javascript   SCRIPT SCHEME
#   compliant               blocked
# link 'data:text/html,<script>alert(1)</script>'
#   noncompliant_blocklist  data         SCRIPT SCHEME
#   noncompliant_unescaped  blocked
#   compliant               blocked
# link 'vbscript:msgbox(1)'
#   noncompliant_blocklist  vbscript     SCRIPT SCHEME
#   noncompliant_unescaped  blocked
#   compliant               blocked
