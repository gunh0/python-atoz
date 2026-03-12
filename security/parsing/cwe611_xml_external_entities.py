"""CWE-611: XML external entities (XXE) — which stdlib parser reads files

https://cwe.mitre.org/data/definitions/611.html

Follow-up to cwe776_xml_entity_expansion. An external entity,
<!ENTITY x SYSTEM "file:///etc/passwd">, asks the parser to fetch a URL and
splice it into the document; reflected back in an error or a response, that
is a file read or SSRF. A parameter entity can load a whole external DTD that
declares such entities, so blocking only the first form is not enough.

Measured below on the stdlib, with a secret file in a temp dir:
ElementTree never fetches (undefined entity error), minidom silently drops
the reference, and sax is safe *by default* since 3.7.1 because
feature_external_ges is off. Code that switches it on "to support entities"
reads local files with both forms. Keep the default, install an
EntityResolver that refuses everything, and reject DOCTYPE for data formats
that never need one.
"""

import io
import tempfile
import xml.dom.minidom
import xml.etree.ElementTree as ET
import xml.sax
import xml.sax.handler
from pathlib import Path


class Collect(xml.sax.ContentHandler):
    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []

    def characters(self, content: str) -> None:
        self.text.append(content)


class RefuseAll(xml.sax.handler.EntityResolver):
    def resolveEntity(self, publicId, systemId):
        raise xml.sax.SAXException("external entity refused")


class NoDTD(xml.sax.handler.LexicalHandler):
    def startDTD(self, name, public_id, system_id):
        raise xml.sax.SAXException("DOCTYPE not allowed")


def sax(doc: str, *, external_ges: bool = False, resolver=None, lexical=None) -> str:
    handler = Collect()
    parser = xml.sax.make_parser()
    parser.setContentHandler(handler)
    parser.setFeature(xml.sax.handler.feature_external_ges, external_ges)
    if resolver:
        parser.setEntityResolver(resolver)
    if lexical:
        parser.setProperty(xml.sax.handler.property_lexical_handler, lexical)
    parser.parse(io.StringIO(doc))
    return "".join(handler.text)


PARSERS = {
    "ElementTree.fromstring":     lambda d: ET.fromstring(d).text or "",
    "minidom.parseString":        lambda d: xml.dom.minidom.parseString(d).documentElement.toxml(),
    "sax default":                lambda d: sax(d),
    "noncompliant sax ges=True":  lambda d: sax(d, external_ges=True),
    "compliant ges+RefuseAll":    lambda d: sax(d, external_ges=True, resolver=RefuseAll()),
    "compliant sax NoDTD":        lambda d: sax(d, lexical=NoDTD()),
}


def outcome(fn, doc: str) -> str:
    try:
        result = fn(doc)
    except ET.ParseError as exc:
        return "ParseError: " + str(exc).split(":")[0]
    except xml.sax.SAXException as exc:
        return f"refused: {exc.getMessage()}"
    return f"LEAKED {result!r}" if "TOP-SECRET" in result else f"no leak, got {result!r}"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        secret = Path(tmp) / "secret.txt"
        secret.write_text("TOP-SECRET")
        dtd = Path(tmp) / "evil.dtd"
        dtd.write_text(f'<!ENTITY leak SYSTEM "{secret.as_uri()}">')
        docs = {
            "general entity": f'<!DOCTYPE r [<!ENTITY x SYSTEM "{secret.as_uri()}">]><r>&x;</r>',
            "parameter entity": f'<!DOCTYPE r [<!ENTITY % p SYSTEM "{dtd.as_uri()}"> %p;]><r>&leak;</r>',
        }
        for label, doc in docs.items():
            print(f"{label}:")
            for name, fn in PARSERS.items():
                print(f"  {name:27} {outcome(fn, doc)}")
        print()
        print("plain document through compliant parsers:",
              sax("<r>ok</r>", external_ges=True, resolver=RefuseAll()), sax("<r>ok</r>", lexical=NoDTD()))


if __name__ == "__main__":
    main()

# Output:
# general entity:
#   ElementTree.fromstring      ParseError: undefined entity &x;
#   minidom.parseString         no leak, got '<r/>'
#   sax default                 no leak, got ''
#   noncompliant sax ges=True   LEAKED 'TOP-SECRET'
#   compliant ges+RefuseAll     refused: external entity refused
#   compliant sax NoDTD         refused: DOCTYPE not allowed
# parameter entity:
#   ElementTree.fromstring      ParseError: undefined entity &leak;
#   minidom.parseString         no leak, got '<r/>'
#   sax default                 no leak, got ''
#   noncompliant sax ges=True   LEAKED 'TOP-SECRET'
#   compliant ges+RefuseAll     refused: external entity refused
#   compliant sax NoDTD         refused: DOCTYPE not allowed
#
# plain document through compliant parsers: ok ok
