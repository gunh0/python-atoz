# requires-python: >=3.14
"""CWE-532: redact secrets in logs with t-strings (PEP 750, Python 3.14)

https://cwe.mitre.org/data/definitions/532.html    (PEP 750: https://peps.python.org/pep-0750/)

A regex log filter (see log_masking_filter.py) can only mask what it can
recognise in the final text, like "token=...". An f-string such as
f"connecting as {user} with {db_password}" flattens the secret into prose
before any filter runs, and nothing marks it as secret any more.

A t-string keeps the structure: t"..." evaluates to a Template whose
interpolations carry the value *and* the source expression. A logging filter
can then mask by expression name (db_password, api_key) or by type (a Secret
wrapper) without guessing from text. One trap: a Template that reaches a
handler without such a filter is formatted with its repr, which prints every
value, so install the filter on the handler before anyone logs t-strings.
"""

import logging
import re
import sys
from string.templatelib import Template

SENSITIVE_NAME = re.compile(r"(?i)(pass(word|wd)?|secret|token|api_?key|credential)")
KEY_VALUE = re.compile(r"(?i)\b(password|secret|token|api[_-]?key)(\s*[=:]\s*)\S+")


class Secret:
    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('***')"


def render(template: Template) -> str:
    parts = []
    for item in template:
        if isinstance(item, str):
            parts.append(item)
            continue
        name = item.expression.rsplit(".", 1)[-1]
        if isinstance(item.value, Secret) or SENSITIVE_NAME.search(name):
            parts.append("***")
            continue
        value = {"r": repr, "s": str, "a": ascii}.get(item.conversion, lambda v: v)(item.value)
        parts.append(format(value, item.format_spec))
    return "".join(parts)


class RegexFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg, record.args = KEY_VALUE.sub(r"\1\2***", record.getMessage()), None
        return True


class TemplateFilter(RegexFilter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, Template):
            record.msg, record.args = render(record.msg), None
        return super().filter(record)  # plain strings still get the regex pass


def make_logger(name: str, filt: logging.Filter) -> logging.Logger:
    log = logging.getLogger(name)
    log.propagate, log.handlers = False, []
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(f"{name:13} %(message)s"))
    handler.addFilter(filt)
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    return log


def main() -> None:
    user, db_password = "svc", "S3cr3t!pw"
    upstream = Secret("ak_7d1f9c2e")  # masked by type, whatever the variable is called
    attempt = 3

    log = make_logger("noncompliant:", RegexFilter())
    log.info(f"connecting as {user} with {db_password}")  # the regex has nothing to anchor on
    log.info(f"retry {attempt} token={db_password}")  # caught, because of the "token=" text
    log.info(t"connecting as {user} with {db_password}")  # Template repr leaks the value

    log = make_logger("compliant:", TemplateFilter())
    log.info(t"connecting as {user} with {db_password}")
    log.info(t"retry {attempt:02d} for {user!r}, upstream {upstream}")
    log.info(f"legacy call site: token={db_password}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: connecting as svc with S3cr3t!pw
# noncompliant: retry 3 token=***
# noncompliant: Template(strings=('connecting as ', ' with ', ''), interpolations=(Interpolation('svc', 'user', None, ''), Interpolation('S3cr3t!pw', 'db_password', None, '')))
# compliant:    connecting as svc with ***
# compliant:    retry 03 for 'svc', upstream ***
# compliant:    legacy call site: token=***
