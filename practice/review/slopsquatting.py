"""Slopsquatting — the package a snippet imports may not exist (yet)

https://en.wikipedia.org/wiki/Slopsquatting

Copied snippets import plausible packages that do not exist on the index:
`flask_auth_tokens_simple`, `colourama`, `fastjsonschema_validator` — typos,
or made-up names copied from snippet to snippet. The same names keep coming
back, so attackers register them on PyPI with a malicious install script and
wait. A developer pastes the code, runs `pip install` for whatever is
missing, and the attacker's code runs.

Before installing anything from a snippet: list what it imports, drop
stdlib and local modules, map import names to distribution names (`yaml` is
PyYAML, `bs4` is beautifulsoup4), and check every name against the index.
Unknown names and look-alikes of popular packages are flagged; a name that
does exist but appeared only weeks ago deserves a second look too. The index
here is a small self-written fixture standing in for PyPI metadata.
"""

import ast
import difflib
import sys
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
    "fastjsonschema-validator": (date(2026, 9, 12), 41),  # registered after the name started circulating
}
IMPORT_TO_DIST = {
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "sklearn": "scikit-learn",
    "dateutil": "python-dateutil",
}
REVIEW_DATE = date(2026, 10, 1)
FLAGGED = {"MISSING", "LOOK-ALIKE", "SUSPICIOUS"}
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


def imported_top_level(source: str) -> list[tuple[int, str]]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [(node.lineno, alias.name.split(".")[0]) for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.append((node.lineno, node.module.split(".")[0]))
    return sorted(found)


def assess(module: str) -> tuple[str, str]:
    if module in sys.stdlib_module_names:
        return "stdlib", ""
    dist = IMPORT_TO_DIST.get(module, module.lower().replace("_", "-"))
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
    imports = imported_top_level(SNIPPET)
    print(f"{len(imports)} absolute imports in the snippet "
          f"(relative 'from . import' skipped)")
    flagged = 0
    for line, module in imports:
        verdict, detail = assess(module)
        flagged += verdict in FLAGGED
        print(f"  line {line:>2}  {module:<25} {verdict:<11} {detail}")
    print(f"{flagged} of {len(imports)} imports need a human before anything is installed")


if __name__ == "__main__":
    main()

# Output:
# 11 absolute imports in the snippet (relative 'from . import' skipped)
#   line  1  json                      stdlib
#   line  2  os                        stdlib
#   line  3  pathlib                   stdlib
#   line  5  requests                  ok          requests
#   line  6  yaml                      ok          pyyaml
#   line  7  bs4                       ok          beautifulsoup4
#   line  8  dateutil                  ok          python-dateutil
#   line  9  colourama                 LOOK-ALIKE  colourama is not on the index; did you mean colorama?
#   line 10  flask_auth_tokens_simple  MISSING     flask-auth-tokens-simple is not on the index: anyone can register it, do not pip install
#   line 11  fastjsonschema_validator  SUSPICIOUS  fastjsonschema-validator exists but is 19 days old with 41 downloads
#   line 12  sklearn                   ok          scikit-learn
# 3 of 11 imports need a human before anything is installed
