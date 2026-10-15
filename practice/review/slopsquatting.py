"""Slopsquatting v2 — check the declared dependencies, not only the imports

https://packaging.python.org/en/latest/specifications/name-normalization/

v1 checked what the snippet imports. The install step reads the
dependency files that came with it, and that is where a nonexistent
name actually gets fetched. v2 parses `requirements.txt` and the
`[project]` table of `pyproject.toml` (with `tomllib`), strips versions,
extras and environment markers, normalises names the way the index does
(`Python_DateUtil` == `python-dateutil`), and runs the same verdicts.

Two more findings come out of having both sides: a direct URL / VCS
requirement skips the index entirely (and every check here), and an import
with no matching declared dependency means someone will `pip install` it by
hand later — the exact moment a squatted name gets installed.
"""

import ast
import difflib
import re
import sys
import tomllib
from datetime import date

# name -> (first release, downloads last month); fixture data, not real statistics.
INDEX = {
    "requests": (date(2011, 2, 14), 400_000_000),
    "pyyaml": (date(2006, 5, 1), 300_000_000),
    "beautifulsoup4": (date(2012, 1, 20), 80_000_000),
    "scikit-learn": (date(2010, 1, 5), 70_000_000),
    "python-dateutil": (date(2003, 9, 1), 350_000_000),
    "colorama": (date(2010, 4, 2), 200_000_000),
    "flask": (date(2010, 4, 6), 90_000_000),
    "flask-jwt-extended": (date(2015, 10, 1), 6_000_000),
    "numpy": (date(2006, 12, 2), 300_000_000),
    "pytest": (date(2010, 11, 1), 250_000_000),
    "fastjsonschema-validator": (date(2026, 9, 12), 41),  # registered after the name started circulating
}
IMPORT_TO_DIST = {
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "sklearn": "scikit-learn",
    "dateutil": "python-dateutil",
}
REVIEW_DATE = date(2026, 10, 1)
FLAGGED = {"MISSING", "LOOK-ALIKE", "SUSPICIOUS", "DIRECT-URL"}
POPULAR = [name for name, (_, downloads) in INDEX.items() if downloads >= 1_000_000]

# Sample code under review: a script that syncs tickets to a dashboard.
SNIPPET = '''\
import json
import os
from pathlib import Path

import requests
import yaml
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
import colourama
import flask_auth_tokens_simple
import fastjsonschema_validator
from sklearn.cluster import KMeans

from . import settings
'''

REQUIREMENTS_TXT = '''\
# shipped alongside the script
requests>=2.31
PyYAML==6.0.1
Python_DateUtil~=2.9          # odd spelling, same project
colourama==0.4.6
fastjsonschema-validator
scikit-learn; python_version >= "3.10"
flask-auth-tokens-simple @ git+https://github.com/example/flask-auth-tokens.git
-r dev-requirements.txt
'''

PYPROJECT_TOML = '''\
[project]
name = "ticket-sync"
version = "0.1.0"
dependencies = ["requests>=2.31", "Flask-JWT-Extended[asymmetric_crypto]>=4", "numpyy>=1.26"]

[project.optional-dependencies]
dev = ["pytest>=8"]
'''

NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirement(line: str) -> tuple[str, bool] | None:
    """Return (normalised name, is_direct_url) or None for comments and options."""
    line = re.sub(r"(^|\s)#.*$", "", line).strip()  # pip: '#' after whitespace starts a comment
    if not line or line.startswith("-"):
        return None
    match = NAME.match(line)
    if not match:
        return None
    return normalize(match.group(1)), " @ " in line or "://" in line


def requirements_txt(text: str) -> list[tuple[str, str, bool]]:
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        parsed = parse_requirement(line)
        if parsed:
            found.append((f"requirements.txt:{n}", *parsed))
    return found


def pyproject(text: str) -> list[tuple[str, str, bool]]:
    project = tomllib.loads(text).get("project", {})
    groups = {"dependencies": project.get("dependencies", [])}
    for extra, deps in project.get("optional-dependencies", {}).items():
        groups[f"optional.{extra}"] = deps
    found = []
    for group, deps in groups.items():
        for dep in deps:
            parsed = parse_requirement(dep)
            if parsed:
                found.append((f"pyproject {group}", *parsed))
    return found


def imported_top_level(source: str) -> list[tuple[int, str]]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [(node.lineno, alias.name.split(".")[0]) for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.append((node.lineno, node.module.split(".")[0]))
    return sorted(found)


def dist_for_import(module: str) -> str | None:
    if module in sys.stdlib_module_names:
        return None
    return IMPORT_TO_DIST.get(module, normalize(module))


def assess(dist: str, direct_url: bool = False) -> tuple[str, str]:
    if direct_url:
        return "DIRECT-URL", f"{dist} is fetched from a URL, bypassing the index and these checks"
    if dist in INDEX:
        first, downloads = INDEX[dist]
        age = (REVIEW_DATE - first).days
        if age < 90:
            return "SUSPICIOUS", f"{dist} exists but is {age} days old with {downloads} downloads"
        return "ok", dist
    near = difflib.get_close_matches(dist, POPULAR, n=1, cutoff=0.75)
    if near:
        return "LOOK-ALIKE", f"{dist} is not on the index; did you mean {near[0]}?"
    return "MISSING", f"{dist} is not on the index: anyone can register it, do not pip install"


def main() -> None:
    declared = requirements_txt(REQUIREMENTS_TXT) + pyproject(PYPROJECT_TOML)
    flagged = 0
    print(f"{len(declared)} declared dependencies")
    for where, dist, direct in declared:
        verdict, detail = assess(dist, direct)
        flagged += verdict in FLAGGED
        print(f"  {where:<27} {verdict:<11} {detail}")
    print(f"{flagged} of {len(declared)} need a human before `pip install`")
    print()

    names = {dist for _, dist, _ in declared}
    undeclared = []
    for line, module in imported_top_level(SNIPPET):
        dist = dist_for_import(module)
        if dist and dist not in names:
            undeclared.append(f"{module} (line {line}, expects {dist})")
    print(f"imported but not declared: {undeclared or 'none'}")
    imported = {dist_for_import(m) for _, m in imported_top_level(SNIPPET)}
    runtime = {dist for where, dist, _ in declared if "optional" not in where}
    unused = sorted(runtime - imported)
    print(f"declared but never imported: {unused}")


if __name__ == "__main__":
    main()

# Output:
# 11 declared dependencies
#   requirements.txt:2          ok          requests
#   requirements.txt:3          ok          pyyaml
#   requirements.txt:4          ok          python-dateutil
#   requirements.txt:5          LOOK-ALIKE  colourama is not on the index; did you mean colorama?
#   requirements.txt:6          SUSPICIOUS  fastjsonschema-validator exists but is 19 days old with 41 downloads
#   requirements.txt:7          ok          scikit-learn
#   requirements.txt:8          DIRECT-URL  flask-auth-tokens-simple is fetched from a URL, bypassing the index and these checks
#   pyproject dependencies      ok          requests
#   pyproject dependencies      ok          flask-jwt-extended
#   pyproject dependencies      LOOK-ALIKE  numpyy is not on the index; did you mean numpy?
#   pyproject optional.dev      ok          pytest
# 4 of 11 need a human before `pip install`
#
# imported but not declared: ['bs4 (line 7, expects beautifulsoup4)']
# declared but never imported: ['flask-jwt-extended', 'numpyy']
