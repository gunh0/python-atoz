"""copy vs deepcopy — ``dict(base)`` copies the top level only

"Start from the default config and override a few values per tenant" is a
classic task, and the usual code is ``cfg = DEFAULTS.copy()`` or
``{**DEFAULTS}`` followed by ``cfg["limits"]["rps"] = 50``. The top-level dict
is new, but the nested dicts and lists are shared, so the first tenant
silently rewrites the defaults for every tenant after it. The grid version of
the same bug is ``[[0] * 3] * 3``: three references to one row.

Review note: a shallow copy is fine only if nothing nested is mutated
afterwards. Otherwise use ``copy.deepcopy``, build fresh structures with a
factory function, or make the defaults immutable (``MappingProxyType``,
tuples, frozen dataclasses) so the mistake raises instead of spreading.
"""

import copy
from types import MappingProxyType


def make_defaults() -> dict:
    return {"name": "default", "limits": {"rps": 10, "burst": 20}, "allow": ["10.0.0.0/8"]}


def tenant_noncompliant(defaults: dict, name: str, rps: int) -> dict:
    cfg = defaults.copy()
    cfg["name"] = name
    cfg["limits"]["rps"] = rps
    cfg["allow"].append(f"{name}.internal")
    return cfg


def tenant_compliant(defaults: dict, name: str, rps: int) -> dict:
    cfg = copy.deepcopy(defaults)
    cfg["name"] = name
    cfg["limits"]["rps"] = rps
    cfg["allow"].append(f"{name}.internal")
    return cfg


def main() -> None:
    defaults = make_defaults()
    tenant_noncompliant(defaults, "acme", 50)
    print("noncompliant: defaults after acme =", defaults)

    defaults = make_defaults()
    acme = tenant_compliant(defaults, "acme", 50)
    print("compliant:    defaults after acme =", defaults)
    print("compliant:    acme                =", acme)

    grid = [[0] * 3] * 3
    grid[0][0] = 1
    print("noncompliant: [[0]*3]*3 after grid[0][0]=1 ->", grid)
    grid = [[0] * 3 for _ in range(3)]
    grid[0][0] = 1
    print("compliant:    comprehension             ->", grid)

    frozen = MappingProxyType({"rps": 10})
    try:
        frozen["rps"] = 99
    except TypeError as exc:
        print("read-only defaults:", type(exc).__name__ + ":", exc)


if __name__ == "__main__":
    main()

# Output:
# noncompliant: defaults after acme = {'name': 'default', 'limits': {'rps': 50, 'burst': 20}, 'allow': ['10.0.0.0/8', 'acme.internal']}
# compliant:    defaults after acme = {'name': 'default', 'limits': {'rps': 10, 'burst': 20}, 'allow': ['10.0.0.0/8']}
# compliant:    acme                = {'name': 'acme', 'limits': {'rps': 50, 'burst': 20}, 'allow': ['10.0.0.0/8', 'acme.internal']}
# noncompliant: [[0]*3]*3 after grid[0][0]=1 -> [[1, 0, 0], [1, 0, 0], [1, 0, 0]]
# compliant:    comprehension             -> [[1, 0, 0], [0, 0, 0], [0, 0, 0]]
# read-only defaults: TypeError: 'mappingproxy' object does not support item assignment
