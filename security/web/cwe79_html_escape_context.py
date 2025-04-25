"""CWE-79: cross-site scripting — escaping depends on where the value lands

https://cwe.mitre.org/data/definitions/79.html

html.escape() is correct for HTML *text* and for *quoted* attribute values,
but only with its default quote=True, which also turns " and ' into entities.
Code that passes quote=False (copied from an old cgi.escape habit) is safe
between tags and broken inside value="...": a single " closes the attribute
and the rest of the input becomes new attributes such as onfocus. An
unquoted attribute is worse: no escaping of quotes helps, because a space is
enough to start a new attribute.

The rules: escape with the default html.escape(), always put attribute values
in quotes, and never put untrusted data into <script>, style, or event
handler attributes at all. To make the result visible without a browser, each
rendering is parsed with html.parser and the tags/attributes it produced are
printed.
"""

import html
from html.parser import HTMLParser

PAYLOADS = [
    "Ada Lovelace",
    "<script>alert(1)</script>",
    '" autofocus onfocus="alert(1)',
    "' autofocus onfocus='alert(1)",
    "x onmouseover=alert(1)",
]


class Inspect(HTMLParser):
    """Record what a browser's tokenizer would build from the markup."""

    def __init__(self) -> None:
        super().__init__()
        self.found: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.found.append("<script>")
        for name, _ in attrs:
            if name not in ("type", "value", "name"):
                self.found.append(name)


def dangerous_parts(markup: str) -> str:
    p = Inspect()
    p.feed(markup)
    p.close()
    return "injected " + ", ".join(p.found) if p.found else "inert"


def renderings(value: str) -> dict[str, str]:
    return {
        "noncompliant text, raw           ": f"<p>Hello {value}</p>",
        "noncompliant attr \"\", quote=False": f'<input name="n" value="{html.escape(value, quote=False)}">',
        "noncompliant attr '', quote=False": f"<input name='n' value='{html.escape(value, quote=False)}'>",
        "noncompliant attr, unquoted      ": f"<input name=n value={html.escape(value)}>",
        "compliant text, escape()         ": f"<p>Hello {html.escape(value)}</p>",
        "compliant attr \"\", escape()      ": f'<input name="n" value="{html.escape(value)}">',
        "compliant attr '', escape()      ": f"<input name='n' value='{html.escape(value)}'>",
    }


def main() -> None:
    for value in PAYLOADS:
        print(f"input {value!r}")
        for label, markup in renderings(value).items():
            print(f"  {label} {dangerous_parts(markup)}")
    print()
    print("escape(quote=True)  ", html.escape("<a href=\"x\" title='y'>&</a>"))
    print("escape(quote=False) ", html.escape("<a href=\"x\" title='y'>&</a>", quote=False))


if __name__ == "__main__":
    main()

# Output:
# input 'Ada Lovelace'
#   noncompliant text, raw            inert
#   noncompliant attr "", quote=False inert
#   noncompliant attr '', quote=False inert
#   noncompliant attr, unquoted       injected lovelace
#   compliant text, escape()          inert
#   compliant attr "", escape()       inert
#   compliant attr '', escape()       inert
# input '<script>alert(1)</script>'
#   noncompliant text, raw            injected <script>
#   noncompliant attr "", quote=False inert
#   noncompliant attr '', quote=False inert
#   noncompliant attr, unquoted       inert
#   compliant text, escape()          inert
#   compliant attr "", escape()       inert
#   compliant attr '', escape()       inert
# input '" autofocus onfocus="alert(1)'
#   noncompliant text, raw            inert
#   noncompliant attr "", quote=False injected autofocus, onfocus
#   noncompliant attr '', quote=False inert
#   noncompliant attr, unquoted       injected autofocus, onfocus
#   compliant text, escape()          inert
#   compliant attr "", escape()       inert
#   compliant attr '', escape()       inert
# input "' autofocus onfocus='alert(1)"
#   noncompliant text, raw            inert
#   noncompliant attr "", quote=False inert
#   noncompliant attr '', quote=False injected autofocus, onfocus
#   noncompliant attr, unquoted       injected autofocus, onfocus
#   compliant text, escape()          inert
#   compliant attr "", escape()       inert
#   compliant attr '', escape()       inert
# input 'x onmouseover=alert(1)'
#   noncompliant text, raw            inert
#   noncompliant attr "", quote=False inert
#   noncompliant attr '', quote=False inert
#   noncompliant attr, unquoted       injected onmouseover
#   compliant text, escape()          inert
#   compliant attr "", escape()       inert
#   compliant attr '', escape()       inert
#
# escape(quote=True)   &lt;a href=&quot;x&quot; title=&#x27;y&#x27;&gt;&amp;&lt;/a&gt;
# escape(quote=False)  &lt;a href="x" title='y'&gt;&amp;&lt;/a&gt;
