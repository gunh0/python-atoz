r"""CWE-918: SSRF allow-lists and URL parser confusion

https://cwe.mitre.org/data/definitions/918.html

Follow-up to cwe918_ssrf_ip_checks. When only some hosts may be fetched
("webhooks to trusted.example only"), the check must look at the same host
the HTTP client will connect to. String checks do not: startswith() is
satisfied by userinfo (https://trusted.example@evil.example), endswith() by
eviltrusted.example. Even urlsplit().hostname can disagree with another
parser: Python keeps "\" inside the authority, while browsers and WHATWG URL
libraries treat it as "/", so "https://evil.example\@trusted.example/" is
trusted.example to Python and evil.example to the browser your redirect or
link hands it to.

Parse once with urlsplit, reject what has no business in the URL (userinfo,
backslashes, other schemes, odd ports, non-ASCII hosts), compare the
lower-cased hostname exactly against the allow-list, and pass the *parsed*
pieces on instead of the original string. The IP checks still apply after
DNS resolution.
"""

from urllib.parse import urlsplit

ALLOWED_HOSTS = {"trusted.example", "api.trusted.example"}
URLS = [
    "https://api.trusted.example/hook",
    "https://trusted.example@evil.example/",
    "https://trusted.example:443@evil.example/",
    "https://trusted.example.evil.example/",
    "https://eviltrusted.example/",
    "https://evil.example\\@trusted.example/",
    "https://evil.example#@trusted.example/",
    "https://TRUSTED.example./hook",
    "https://trusted.ex\u0430mple/",          # CYRILLIC SMALL LETTER A
    "http://trusted.example:6379/",
    "file://trusted.example/etc/passwd",
]


def python_host(url: str) -> str:
    return urlsplit(url).hostname or "-"


def whatwg_host(url: str) -> str:
    """Rough model of a browser: a backslash is a slash, hosts are IDNA-encoded."""
    host = urlsplit(url.replace("\\", "/")).hostname or "-"
    try:
        return host.encode("idna").decode()
    except UnicodeError:
        return host


def noncompliant_startswith(url: str) -> bool:
    return url.startswith(("https://trusted.example", "https://api.trusted.example"))


def noncompliant_endswith(url: str) -> bool:
    return (urlsplit(url).hostname or "").endswith("trusted.example")


def noncompliant_hostname_only(url: str) -> bool:
    return urlsplit(url).hostname in ALLOWED_HOSTS


def compliant(url: str) -> bool:
    if "\\" in url or not url.isascii():
        return False
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.username is not None or parts.password is not None:
        return False
    if parts.port not in (None, 443):
        return False
    host = (parts.hostname or "").rstrip(".")
    return host in ALLOWED_HOSTS


def main() -> None:
    checks = (noncompliant_startswith, noncompliant_endswith, noncompliant_hostname_only, compliant)
    print(f"{'url':44}{'python host':30}{'browser host':30}{'start end host  ok'}")
    for url in URLS:
        marks = "  ".join("Y" if fn(url) else "." for fn in checks)
        print(f"{url!r:44}{python_host(url):30}{whatwg_host(url):30}{marks:>4}")
    print()
    print("Y = allowed. Only the first row and the TRUSTED.example. row should be;")
    print("every other Y is a host, port or scheme the allow-list meant to exclude.")


if __name__ == "__main__":
    main()

# Output:
# url                                         python host                   browser host                  start end host  ok
# 'https://api.trusted.example/hook'          api.trusted.example           api.trusted.example           Y  Y  Y  Y
# 'https://trusted.example@evil.example/'     evil.example                  evil.example                  Y  .  .  .
# 'https://trusted.example:443@evil.example/' evil.example                  evil.example                  Y  .  .  .
# 'https://trusted.example.evil.example/'     trusted.example.evil.example  trusted.example.evil.example  Y  .  .  .
# 'https://eviltrusted.example/'              eviltrusted.example           eviltrusted.example           .  Y  .  .
# 'https://evil.example\\@trusted.example/'   trusted.example               evil.example                  .  Y  Y  .
# 'https://evil.example#@trusted.example/'    evil.example                  evil.example                  .  .  .  .
# 'https://TRUSTED.example./hook'             trusted.example.              trusted.example.              .  .  .  Y
# 'https://trusted.exаmple/'                  trusted.exаmple               trusted.xn--exmple-4nf        .  .  .  .
# 'http://trusted.example:6379/'              trusted.example               trusted.example               .  Y  Y  .
# 'file://trusted.example/etc/passwd'         trusted.example               trusted.example               .  Y  Y  .
#
# Y = allowed. Only the first row and the TRUSTED.example. row should be;
# every other Y is a host, port or scheme the allow-list meant to exclude.
