"""SNMP BER codec v2: decode a GetResponse, application types, hostile input

v1 encoded a GetRequest and decoded it back. A real poller spends its time
on the other direction -- parsing whatever comes back from the network --
and that needs two more things.

SNMP's application types: IpAddress (0x40), Counter32 (0x41), Gauge32
(0x42), TimeTicks (0x43), Counter64 (0x46), plus the v2c exception values
noSuchObject/noSuchInstance/endOfMibView (0x80-0x82) that appear in place
of a value. Counters are *unsigned*, so 0xDEADBEEF is sent as 00 de ad be ef;
decoding them as signed INTEGER turns big counters negative.

And a decoder that treats every byte as untrusted: a UDP packet can be
truncated, claim a length longer than itself, use BER's indefinite length
(forbidden in SNMP), or a 9-byte length meant to make you allocate
gigabytes. Each of those must raise one clear error, never IndexError or a
silently short value. (In 2002 the PROTOS SNMP test suite, CERT CA-2002-03,
crashed products from dozens of vendors with exactly this kind of packet.)
"""

INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
IP_ADDRESS, COUNTER32, GAUGE32, TIMETICKS, COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x46
NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW = 0x80, 0x81, 0x82
GET_REQUEST, GET_RESPONSE = 0xA0, 0xA2
NAMES = {INTEGER: "INTEGER", OCTET_STRING: "OCTET STRING", NULL: "NULL", OID: "OID",
         SEQUENCE: "SEQUENCE", GET_REQUEST: "GetRequest-PDU", GET_RESPONSE: "GetResponse-PDU",
         IP_ADDRESS: "IpAddress", COUNTER32: "Counter32", GAUGE32: "Gauge32",
         TIMETICKS: "Timeticks", COUNTER64: "Counter64", NO_SUCH_OBJECT: "noSuchObject",
         NO_SUCH_INSTANCE: "noSuchInstance", END_OF_MIB_VIEW: "endOfMibView"}
UNSIGNED = {COUNTER32, GAUGE32, TIMETICKS, COUNTER64}
ERROR_STATUS = {0: "noError", 1: "tooBig", 2: "noSuchName", 5: "genErr", 6: "noAccess"}
MAX_DEPTH = 8


class BerError(ValueError):
    pass


# ---------------------------------------------------------------- encoding

def enc_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + enc_length(len(value)) + value


def enc_integer(n: int, tag: int = INTEGER) -> bytes:
    magnitude = n if n >= 0 else ~n  # -128 fits in one byte, +128 does not
    size = (magnitude.bit_length() + 8) // 8  # +1 bit for the sign
    return tlv(tag, n.to_bytes(size, "big", signed=True))


def enc_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.strip(".").split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(chunk))
    return tlv(OID, bytes(out))


def get_request(community: str, request_id: int, oids: list[str]) -> bytes:
    varbinds = b"".join(tlv(SEQUENCE, enc_oid(o) + tlv(NULL, b"")) for o in oids)
    pdu = tlv(GET_REQUEST, enc_integer(request_id) + enc_integer(0) + enc_integer(0)
              + tlv(SEQUENCE, varbinds))
    return tlv(SEQUENCE, enc_integer(1) + tlv(OCTET_STRING, community.encode()) + pdu)


# ---------------------------------------------------------------- decoding

def dec_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos + 2 > len(data):
        raise BerError(f"truncated header at offset {pos}")
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first == 0x80:
        raise BerError(f"indefinite length at offset {pos - 2} (not allowed in SNMP)")
    if first & 0x80:
        n = first & 0x7F
        if n > 4:
            raise BerError(f"{n}-byte length field at offset {pos - 2}")
        if pos + n > len(data):
            raise BerError(f"truncated length at offset {pos - 2}")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        length = first
    if pos + length > len(data):
        raise BerError(f"tag {tag:#04x} claims {length} bytes, {len(data) - pos} available")
    return tag, data[pos:pos + length], pos + length


def dec_oid(value: bytes) -> str:
    if not value or value[-1] & 0x80:
        raise BerError("malformed OID")
    arcs = [value[0] // 40, value[0] % 40]
    arc = 0
    for byte in value[1:]:
        arc = (arc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(arc)
            arc = 0
    return ".".join(map(str, arcs))


def dec_value(tag: int, value: bytes):
    if tag == INTEGER:
        return int.from_bytes(value, "big", signed=True)
    if tag in UNSIGNED:
        return int.from_bytes(value, "big")
    if tag == OCTET_STRING:
        return value.decode("ascii", "replace")
    if tag == OID:
        return dec_oid(value)
    if tag == IP_ADDRESS:
        return ".".join(map(str, value))
    return None  # NULL and the v2c exceptions carry no value


def decode(data: bytes, depth: int = 0):
    if depth > MAX_DEPTH:
        raise BerError("nesting too deep")
    items, pos = [], 0
    while pos < len(data):
        tag, value, pos = dec_tlv(data, pos)
        name = NAMES.get(tag, f"tag {tag:#04x}")
        items.append((name, decode(value, depth + 1) if tag & 0x20 else dec_value(tag, value)))
    return items


def timeticks(t: int) -> str:
    days, rest = divmod(t, 8_640_000)
    hours, rest = divmod(rest, 360_000)
    minutes, rest = divmod(rest, 6_000)
    return f"{days} days, {hours:02d}:{minutes:02d}:{rest / 100:05.2f}"


# A GetResponse from edge-sw02 (request-id 0x1a2b), as captured off the wire.
# Note "81 40" in the ipAdEntAddr OID: arc 192 needs two base-128 bytes.
RESPONSE = bytes.fromhex(
    "30819702010104067075626c6963a2818902021a2b020100020100307d301006"
    "082b06010201010300430404d7ff743014060b2b060102011f01010106014605"
    "468b2762793013060a2b060102010202010a01410500deadbeef301506082b06"
    "0102010105000409656467652d737730323016060e2b06010201041401018140"
    "00020a4004c000020a300f060b2b060102011f01010112638100"
)


def main() -> None:
    packet = get_request("public", 1, ["1.3.6.1.2.1.1.1.0"])
    reference = bytes.fromhex("302602010104067075626c6963a019020101020100020100"
                              "300e300c06082b060102010101000500")
    print("v1 GetRequest still matches reference:", packet == reference)

    print()
    message = decode(RESPONSE)[0][1]
    pdu_name, pdu = message[2]
    print(f"{pdu_name} community={message[1][1]} request-id={pdu[0][1]:#x} "
          f"error-status={ERROR_STATUS.get(pdu[1][1], pdu[1][1])}")
    for _, varbind in pdu[3][1]:
        (_, oid), (kind, value) = varbind
        shown = timeticks(value) if kind == "Timeticks" else value
        print(f"  {oid:<32} {kind:<14} {'' if shown is None else shown}")

    print()
    print("Counter32 0xdeadbeef as signed INTEGER would be:",
          int.from_bytes(bytes.fromhex("deadbeef"), "big", signed=True))

    print()
    hostile = {
        "truncated packet": RESPONSE[:-5],
        "length larger than packet": bytes.fromhex("3064020101"),
        "indefinite length": bytes.fromhex("3080020101000000"),
        "9-byte length field": bytes.fromhex("3089ffffffffffffffffff"),
        "OID ending mid-arc": bytes.fromhex("3004060281ff"),
        "nesting bomb": bytes.fromhex("3016301430123010300e300c300a30083006300430023000"),
    }
    for label, data in hostile.items():
        try:
            decode(data)
            print(f"{label:<26} decoded (unexpected)")
        except BerError as exc:
            print(f"{label:<26} BerError: {exc}")


if __name__ == "__main__":
    main()

# Output:
# v1 GetRequest still matches reference: True
#
# GetResponse-PDU community=public request-id=0x1a2b error-status=noError
#   1.3.6.1.2.1.1.3.0                Timeticks      9 days, 09:44:05.00
#   1.3.6.1.2.1.31.1.1.1.6.1         Counter64      302982324857
#   1.3.6.1.2.1.2.2.1.10.1           Counter32      3735928559
#   1.3.6.1.2.1.1.5.0                OCTET STRING   edge-sw02
#   1.3.6.1.2.1.4.20.1.1.192.0.2.10  IpAddress      192.0.2.10
#   1.3.6.1.2.1.31.1.1.1.18.99       noSuchInstance
#
# Counter32 0xdeadbeef as signed INTEGER would be: -559038737
#
# truncated packet           BerError: tag 0x30 claims 151 bytes, 146 available
# length larger than packet  BerError: tag 0x30 claims 100 bytes, 3 available
# indefinite length          BerError: indefinite length at offset 0 (not allowed in SNMP)
# 9-byte length field        BerError: 9-byte length field at offset 0
# OID ending mid-arc         BerError: malformed OID
# nesting bomb               BerError: nesting too deep
