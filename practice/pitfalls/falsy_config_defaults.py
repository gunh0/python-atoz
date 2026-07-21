"""Truthiness in config defaults — ``value or default`` throws away 0, "" and []

The most common idiom for defaults is ``timeout = cfg.get("timeout") or 30``.
It treats every falsy value as "missing", so an operator who sets
``timeout: 0`` (no timeout), ``retries: 0`` (fail fast), ``prefix: ""`` or
``allow: []`` (deny all) silently gets the default instead. The security
version is the empty allow-list that becomes "allow the defaults". The
string twin is ``bool(os.environ["DEBUG"])``: ``bool("false")`` is True.

Review note: distinguish "absent" from "falsy". Use ``cfg.get(key, default)``
when absent means default, ``if value is None`` when null means default, and a
sentinel object when ``None`` is itself a legal value. Parse booleans from
strings explicitly and reject anything unexpected.
"""

_MISSING = object()

DEFAULTS = {"timeout": 30, "retries": 3, "prefix": "app-", "allow": ["10.0.0.0/8"], "debug": False}
OPERATOR_CONFIG = {"timeout": 0, "retries": 0, "prefix": "", "allow": [], "debug": "false"}


def load_noncompliant(cfg: dict) -> dict:
    return {
        "timeout": cfg.get("timeout") or DEFAULTS["timeout"],
        "retries": cfg.get("retries") or DEFAULTS["retries"],
        "prefix": cfg.get("prefix") or DEFAULTS["prefix"],
        "allow": cfg.get("allow") or DEFAULTS["allow"],
        "debug": bool(cfg.get("debug", DEFAULTS["debug"])),
    }


def parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError(f"not a boolean: {value!r}")


def load_compliant(cfg: dict) -> dict:
    out = {}
    for key, default in DEFAULTS.items():
        value = cfg.get(key, _MISSING)
        out[key] = default if value is _MISSING or value is None else value
    out["debug"] = parse_bool(out["debug"])
    return out


def main() -> None:
    print("operator config:", OPERATOR_CONFIG)
    print("noncompliant:   ", load_noncompliant(OPERATOR_CONFIG))
    print("compliant:      ", load_compliant(OPERATOR_CONFIG))
    print("compliant ({}): ", load_compliant({}))
    print("compliant (null timeout):", load_compliant({"timeout": None})["timeout"])

    print("bool('false') =", bool("false"), " bool('0') =", bool("0"), " parse_bool('false') =", parse_bool("false"))
    try:
        parse_bool("ture")
    except ValueError as exc:
        print("parse_bool('ture') ->", type(exc).__name__ + ":", exc)


if __name__ == "__main__":
    main()

# Output:
# operator config: {'timeout': 0, 'retries': 0, 'prefix': '', 'allow': [], 'debug': 'false'}
# noncompliant:    {'timeout': 30, 'retries': 3, 'prefix': 'app-', 'allow': ['10.0.0.0/8'], 'debug': True}
# compliant:       {'timeout': 0, 'retries': 0, 'prefix': '', 'allow': [], 'debug': False}
# compliant ({}):  {'timeout': 30, 'retries': 3, 'prefix': 'app-', 'allow': ['10.0.0.0/8'], 'debug': False}
# compliant (null timeout): 30
# bool('false') = True  bool('0') = True  parse_bool('false') = False
# parse_bool('ture') -> ValueError: not a boolean: 'ture'
