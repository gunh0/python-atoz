"""CWE-776: XML entity expansion — what the stdlib parsers really accept

https://cwe.mitre.org/data/definitions/776.html   (billion laughs, quadratic blowup)

An internal DTD can define entities that reference other entities, so a few
hundred bytes expand to gigabytes ("billion laughs"), or one 10 KB entity
referenced a thousand times does the same without nesting ("quadratic
blowup"). ElementTree, minidom and sax all sit on expat, and since expat
2.4 expat has a built-in guard: once expansion passes an activation
threshold of 8 MiB, it aborts if output/input exceeds 100x.

So the stdlib is no longer exploitable to the gigabyte, but below the
threshold it expands without complaint: 3 MB from a 400-byte document, 8 MB
from 12 KB, per request. The table is measured at run time (same result on
the expat versions bundled with 3.13, 3.14 and 3.15 here). Data formats
almost never need a DTD: reject DOCTYPE outright (ElementTree calls a
target's doctype() before any entity is declared), or tighten expat's limits
where pyexpat exposes them.
"""

import io
import pyexpat
import xml.dom.minidom
import xml.etree.ElementTree as ET
import xml.sax


def laughs(depth: int, width: int = 10) -> str:
    ents = ['<!ENTITY e0 "lol">'] + [
        f'<!ENTITY e{i} "{f"&e{i - 1};" * width}">' for i in range(1, depth + 1)]
    return f'<?xml version="1.0"?><!DOCTYPE r [{"".join(ents)}]><r>&e{depth};</r>'


def quadratic(size: int, refs: int) -> str:
    return f'<!DOCTYPE r [<!ENTITY a "{"A" * size}">]><r>{"&a;" * refs}</r>'


class Text(xml.sax.ContentHandler):
    def __init__(self) -> None:
        super().__init__()
        self.n = 0

    def characters(self, content: str) -> None:
        self.n += len(content)


def sax_len(doc: str) -> int:
    h = Text()
    xml.sax.parseString(doc.encode(), h)
    return h.n


PARSERS = {
    "ElementTree": lambda d: len(ET.fromstring(d).text),
    "minidom": lambda d: len(xml.dom.minidom.parseString(d).documentElement.firstChild.data),
    "sax": sax_len,
}


def outcome(fn, doc: str) -> str:
    try:
        return f"{fn(doc):>9,} chars"
    except (ET.ParseError, pyexpat.ExpatError, xml.sax.SAXParseException) as exc:
        return "amplification" if "amplification" in str(exc) else type(exc).__name__


class NoDTD(ET.TreeBuilder):
    def doctype(self, name, pubid, system):
        raise ValueError("DOCTYPE not allowed")


def compliant_parse(doc: str) -> ET.Element:
    return ET.fromstring(doc, parser=ET.XMLParser(target=NoDTD()))


def compliant_tight_expat(doc: str, factor: float = 10.0, threshold: int = 64 * 1024) -> int:
    p = pyexpat.ParserCreate()
    p.SetBillionLaughsAttackProtectionMaximumAmplification(factor)
    p.SetBillionLaughsAttackProtectionActivationThreshold(threshold)
    total = 0

    def chars(data: str) -> None:
        nonlocal total
        total += len(data)

    p.CharacterDataHandler = chars
    p.Parse(doc, True)
    return total


def main() -> None:
    cases = [(f"laughs depth {d}", laughs(d)) for d in (3, 5, 6, 7, 9)]
    cases += [("quadratic 10KB x 700", quadratic(10_000, 700)),
              ("quadratic 10KB x 900", quadratic(10_000, 900))]
    print(f"{'document':22}{'input':>8}  " + "".join(f"{n:>17}" for n in PARSERS))
    for label, doc in cases:
        row = "".join(f"{outcome(fn, doc):>17}" for fn in PARSERS.values())
        print(f"{label:22}{len(doc):>8,}  {row}")
    print()
    for label, doc in [("plain <r>hi</r>", "<r>hi</r>"), ("laughs depth 6", laughs(6))]:
        try:
            print(f"compliant no-DTD      {label:16} -> text {compliant_parse(doc).text!r}")
        except ValueError as exc:
            print(f"compliant no-DTD      {label:16} -> refused: {exc}")
    for label, doc in [("laughs depth 3", laughs(3)), ("laughs depth 6", laughs(6))]:
        print(f"compliant tight expat {label:16} -> {outcome(compliant_tight_expat, doc).strip()}")


if __name__ == "__main__":
    main()

# Output:
# document                 input        ElementTree          minidom              sax
# laughs depth 3             230        3,000 chars      3,000 chars      3,000 chars
# laughs depth 5             340      300,000 chars    300,000 chars    300,000 chars
# laughs depth 6             395    3,000,000 chars  3,000,000 chars  3,000,000 chars
# laughs depth 7             450      amplification    amplification    amplification
# laughs depth 9             560      amplification    amplification    amplification
# quadratic 10KB x 700    12,136    7,000,000 chars  7,000,000 chars  7,000,000 chars
# quadratic 10KB x 900    12,736      amplification    amplification    amplification
#
# compliant no-DTD      plain <r>hi</r>  -> text 'hi'
# compliant no-DTD      laughs depth 6   -> refused: DOCTYPE not allowed
# compliant tight expat laughs depth 3   -> 3,000 chars
# compliant tight expat laughs depth 6   -> amplification
