"""CWE-1289: Unicode usernames — compare canonical forms, block confusables

https://cwe.mitre.org/data/definitions/1289.html   (improper validation of unsafe equivalence)

"Is this username taken?" compared as raw strings says "ａｄｍｉｎ"
(fullwidth), "Admin", "ad<ZWSP>min" (zero-width space) and "аdmin"
(Cyrillic а) are all new. Some other component will disagree: a
password-reset flow, a database collation or an LDAP gateway that applies
NFKC or case folding maps the first three onto the real admin account, which
is how account takeovers like Spotify's 2013 "canonical username" bug
happen. The Cyrillic one survives every normalisation and is a pure
look-alike for phishing.

Derive one canonical key: NFKC, then casefold(), then NFKC again (casefold
can produce unnormalised output). Enforce uniqueness on that key, reject
invisible/format characters and mixed scripts, and keep the original only
for display. If you do not need Unicode usernames, an ASCII allow-list on the
canonical key is simplest. The stdlib has no UTS #39 confusables table; the
script check here uses unicodedata.name() as a coarse approximation.
"""

import re
import unicodedata

EXISTING = {"admin", "alice"}
ATTEMPTS = [
    "bob",
    "admin",
    "Admin",
    "\uff41\uff44\uff4d\uff49\uff4e",        # FULLWIDTH a d m i n
    "ad\u200bmin",                           # ZERO WIDTH SPACE
    "\u0430dmin",                            # CYRILLIC SMALL LETTER A
    "\u1d2c\u1d30\u1d39\u1d35\u1d3a",        # MODIFIER LETTER CAPITAL A D M I N
    "a\u0301lice",                           # a + COMBINING ACUTE (NFC: á)
    "stra\xdfe",                             # ß casefolds to ss
    "\u0441\u043e\u0440\u0435",              # all-Cyrillic, reads as "cope": only UTS #39 catches it
]


def canonical(name: str) -> str:
    return unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", name).casefold())


def scripts(name: str) -> set[str]:
    found = set()
    for ch in name:
        if ch.isalpha():
            found.add(unicodedata.name(ch, "UNKNOWN").split()[0])   # LATIN, CYRILLIC, ...
    return found


def noncompliant_register(name: str, taken: set[str]) -> str:
    return "rejected: taken" if name in taken else "accepted"


def compliant_register(name: str, taken_keys: set[str]) -> str:
    if any(unicodedata.category(ch) in ("Cf", "Cc", "Zs", "Zl", "Zp") for ch in name):
        return "rejected: invisible/control character"
    key = canonical(name)
    if not re.fullmatch(r"\w{3,32}", key) or any(unicodedata.combining(c) for c in key):
        return "rejected: characters"
    if len(scripts(key)) > 1:
        return f"rejected: mixed scripts {sorted(scripts(key))}"
    if key in taken_keys:
        return f"rejected: taken (key {ascii(key)})"
    return f"accepted (key {ascii(key)})"


def main() -> None:
    taken_keys = {canonical(n) for n in EXISTING}
    print(f"existing users: {sorted(EXISTING)}")
    for name in ATTEMPTS:
        print(f"register {ascii(name)}")
        print(f"  noncompliant raw compare: {noncompliant_register(name, EXISTING)}")
        print(f"  NFKC+casefold would be:   {ascii(canonical(name))}")
        print(f"  compliant:                {compliant_register(name, taken_keys)}")


if __name__ == "__main__":
    main()

# Output:
# existing users: ['admin', 'alice']
# register 'bob'
#   noncompliant raw compare: accepted
#   NFKC+casefold would be:   'bob'
#   compliant:                accepted (key 'bob')
# register 'admin'
#   noncompliant raw compare: rejected: taken
#   NFKC+casefold would be:   'admin'
#   compliant:                rejected: taken (key 'admin')
# register 'Admin'
#   noncompliant raw compare: accepted
#   NFKC+casefold would be:   'admin'
#   compliant:                rejected: taken (key 'admin')
# register '\uff41\uff44\uff4d\uff49\uff4e'
#   noncompliant raw compare: accepted
#   NFKC+casefold would be:   'admin'
#   compliant:                rejected: taken (key 'admin')
# register 'ad\u200bmin'
#   noncompliant raw compare: accepted
#   NFKC+casefold would be:   'ad\u200bmin'
#   compliant:                rejected: invisible/control character
# register '\u0430dmin'
#   noncompliant raw compare: accepted
#   NFKC+casefold would be:   '\u0430dmin'
#   compliant:                rejected: mixed scripts ['CYRILLIC', 'LATIN']
# register '\u1d2c\u1d30\u1d39\u1d35\u1d3a'
#   noncompliant raw compare: accepted
#   NFKC+casefold would be:   'admin'
#   compliant:                rejected: taken (key 'admin')
# register 'a\u0301lice'
#   noncompliant raw compare: accepted
#   NFKC+casefold would be:   '\xe1lice'
#   compliant:                accepted (key '\xe1lice')
# register 'stra\xdfe'
#   noncompliant raw compare: accepted
#   NFKC+casefold would be:   'strasse'
#   compliant:                accepted (key 'strasse')
# register '\u0441\u043e\u0440\u0435'
#   noncompliant raw compare: accepted
#   NFKC+casefold would be:   '\u0441\u043e\u0440\u0435'
#   compliant:                accepted (key '\u0441\u043e\u0440\u0435')
