"""CWE-1336: template injection with str.format — attribute traversal leaks secrets

https://cwe.mitre.org/data/definitions/1336.html   (CWE-134: externally-controlled format string)

Letting users (tenant admins, marketing, a CMS field) write message templates
like "Hi {user.name}" and rendering them with template.format(user=user) looks
harmless because format() cannot call functions. It does not need to: a
replacement field may follow attributes and indexes, so
{user.__init__.__globals__[SECRET_KEY]} walks from the object to its
method, to the module dictionary the method was defined in, and prints any
global there. Format specs add a cheap memory DoS: {user.name:>9999999}
renders 10 MB, and each extra digit multiplies that by ten.

For user-authored templates use string.Template: $name / ${name} with
identifier-only placeholders, rendered against a flat dict of strings that
you built for the purpose. If you must keep {} syntax, use a Formatter
subclass that rejects dotted/indexed fields and caps the field width.
"""

import re
import string
from dataclasses import dataclass

SECRET_KEY = "flask-secret-0f3a9c"   # any module global is reachable
DATABASE_URL = "postgres://app:hunter2@db/app"


@dataclass
class User:
    name: str
    email: str

    def display(self) -> str:
        return self.name.title()


TEMPLATES = [
    "Hi {user.name}, we sent a receipt to {user.email}.",
    "Key: {user.display.__globals__[SECRET_KEY]}",
    "DB: {user.__init__.__globals__[DATABASE_URL]}",
    "Class: {user.__class__.__mro__}",
    "Pad: {user.name:>9999999}",
]


def noncompliant(template: str, user: User) -> str:
    out = template.format(user=user)
    return out if len(out) < 120 else f"<{len(out):,} chars rendered>"


class StrictFormatter(string.Formatter):
    """{} syntax kept, but only plain names from the mapping and short widths."""

    def get_field(self, field_name, args, kwargs):
        if not re.fullmatch(r"[a-z_]+", field_name):
            raise ValueError(f"field {field_name!r} not allowed")
        return kwargs[field_name], field_name

    def format_field(self, value, format_spec):
        if re.search(r"\d{3,}", format_spec):
            raise ValueError(f"format spec {format_spec!r} not allowed")
        return super().format_field(value, format_spec)


def context(user: User) -> dict[str, str]:
    """The only data a template may see: flat, pre-rendered strings."""
    return {"name": user.name, "email": user.email}


def compliant_template(template: str, user: User) -> str:
    # The admin-facing syntax is $name; translate the old {user.x} spelling for the demo.
    tmpl = string.Template(re.sub(r"\{user\.(\w+)\}", r"${\1}", template))
    try:
        return tmpl.substitute(context(user))
    except (KeyError, ValueError) as exc:
        return f"rejected: {type(exc).__name__}"


def compliant_strict(template: str, user: User) -> str:
    try:
        return StrictFormatter().format(template.replace("user.", ""), **context(user))
    except (KeyError, ValueError) as exc:
        return f"rejected: {exc}"


def main() -> None:
    user = User("ada", "ada@example.com")
    for template in TEMPLATES:
        print(f"template {template!r}")
        print(f"  noncompliant format:  {noncompliant(template, user)}")
        print(f"  compliant Template:   {compliant_template(template, user)}")
        print(f"  compliant strict fmt: {compliant_strict(template, user)}")
    print()
    t = string.Template("Hi $name, ${name}'s order ${user.__init__} is $$5")
    print("safe_substitute keeps unknown/invalid placeholders as text:")
    print(" ", t.safe_substitute(name="ada"))


if __name__ == "__main__":
    main()

# Output:
# template 'Hi {user.name}, we sent a receipt to {user.email}.'
#   noncompliant format:  Hi ada, we sent a receipt to ada@example.com.
#   compliant Template:   Hi ada, we sent a receipt to ada@example.com.
#   compliant strict fmt: Hi ada, we sent a receipt to ada@example.com.
# template 'Key: {user.display.__globals__[SECRET_KEY]}'
#   noncompliant format:  Key: flask-secret-0f3a9c
#   compliant Template:   Key: {user.display.__globals__[SECRET_KEY]}
#   compliant strict fmt: rejected: field 'display.__globals__[SECRET_KEY]' not allowed
# template 'DB: {user.__init__.__globals__[DATABASE_URL]}'
#   noncompliant format:  DB: postgres://app:hunter2@db/app
#   compliant Template:   DB: {user.__init__.__globals__[DATABASE_URL]}
#   compliant strict fmt: rejected: field '__init__.__globals__[DATABASE_URL]' not allowed
# template 'Class: {user.__class__.__mro__}'
#   noncompliant format:  Class: (<class '__main__.User'>, <class 'object'>)
#   compliant Template:   Class: {user.__class__.__mro__}
#   compliant strict fmt: rejected: field '__class__.__mro__' not allowed
# template 'Pad: {user.name:>9999999}'
#   noncompliant format:  <10,000,004 chars rendered>
#   compliant Template:   Pad: {user.name:>9999999}
#   compliant strict fmt: rejected: format spec '>9999999' not allowed
#
# safe_substitute keeps unknown/invalid placeholders as text:
#   Hi ada, ada's order ${user.__init__} is $5
