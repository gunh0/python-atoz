"""CWE-352: CSRF — the double-submit token has to be signed and bound to the session

https://cwe.mitre.org/data/definitions/352.html    (OWASP CSRF Prevention Cheat Sheet)

Browsers attach cookies to cross-site requests, so a form on evil.example can
POST to bank.example/transfer with the victim's session. The double-submit
pattern adds a random token in a cookie *and* in the form body: a cross-site
page cannot read the cookie, so it cannot copy it into the form.

The naive version just checks cookie == form. But cookies can be *written* by
anyone who controls a sibling subdomain or can inject a Set-Cookie header,
and an attacker who sets csrf=known gets to send known in the form too. The
signed variant makes the token HMAC(secret, session_id, nonce): a token
planted from outside does not verify, and a token minted for the attacker's
own session is useless in the victim's.
"""

import hashlib
import hmac
import secrets

SECRET = bytes.fromhex("5f1c9e2a7b3d4e6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7")


def make_signed_token(session_id: str) -> str:
    nonce = secrets.token_hex(16)
    mac = hmac.new(SECRET, f"{len(session_id)}!{session_id}!{nonce}".encode(), hashlib.sha256)
    return f"{mac.hexdigest()}.{nonce}"


def no_check(req: dict) -> bool:
    return "session" in req["cookies"]


def noncompliant_double_submit(req: dict) -> bool:
    cookie, form = req["cookies"].get("csrf", ""), req["form"].get("csrf", "")
    return no_check(req) and bool(cookie) and hmac.compare_digest(cookie, form)


def compliant_signed(req: dict) -> bool:
    session = req["cookies"].get("session")
    cookie, form = req["cookies"].get("csrf", ""), req["form"].get("csrf", "")
    if not session or not cookie or not hmac.compare_digest(cookie, form):
        return False
    mac, _, nonce = form.partition(".")
    expected = hmac.new(SECRET, f"{len(session)}!{session}!{nonce}".encode(), hashlib.sha256)
    return hmac.compare_digest(mac, expected.hexdigest())


def main() -> None:
    victim = secrets.token_urlsafe(32)
    attacker_token = make_signed_token(secrets.token_urlsafe(32))  # attacker logs in as themself
    issued = {no_check: secrets.token_hex(16), noncompliant_double_submit: secrets.token_hex(16),
              compliant_signed: make_signed_token(victim)}  # what each scheme hands the victim

    scenarios = {  # scenario -> builds the request, given the victim's real token
        "same-site form": lambda tok: {"cookies": {"session": victim, "csrf": tok}, "form": {"csrf": tok}},
        "cross-site POST, no token": lambda tok: {"cookies": {"session": victim, "csrf": tok}, "form": {}},
        "cookie injected: csrf=known": lambda tok: {"cookies": {"session": victim, "csrf": "known"},
                                                    "form": {"csrf": "known"}},
        "attacker's own signed token": lambda tok: {"cookies": {"session": victim, "csrf": attacker_token},
                                                    "form": {"csrf": attacker_token}},
    }
    print(f"{'request':30} {'no check':9} {'naive':9} signed")
    for name, build in scenarios.items():
        verdicts = ["accept" if check(build(token)) else "reject" for check, token in issued.items()]
        print(f"{name:30} {verdicts[0]:9} {verdicts[1]:9} {verdicts[2]}")


if __name__ == "__main__":
    main()

# Output:
# request                        no check  naive     signed
# same-site form                 accept    accept    accept
# cross-site POST, no token      accept    reject    reject
# cookie injected: csrf=known    accept    accept    reject
# attacker's own signed token    accept    accept    reject
