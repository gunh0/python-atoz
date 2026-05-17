"""SNMP on the wire: a hand-written ASN.1 BER encoder/decoder for a GetRequest

An SNMP packet is nested BER TLVs: a SEQUENCE holding version, community and
a PDU, the PDU holding request-id, error fields and a list of (OID, value)
pairs. Writing the encoder once by hand makes packet captures readable and
explains the classic interop bugs:

- lengths under 128 are one byte; longer ones are 0x80|n followed by n
  length bytes ("long form") -- a 200-byte community breaks naive code;
- INTEGER is minimal two's complement, so 128 encodes as 00 80, not 80;
- an OID packs the first two arcs into one byte (40*x + y) and writes each
  further arc in base 128, high bit set on all but the last byte, so 2021
  becomes 8f 65.

The check at the end is the important part: encode, compare with a known
byte string, decode what we produced and get the same structure back.
"""

INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
GET_REQUEST = 0xA0  # context-specific, constructed, tag 0
NAMES = {INTEGER: "INTEGER", OCTET_STRING: "OCTET STRING", NULL: "NULL", OID: "OID",
         SEQUENCE: "SEQUENCE", GET_REQUEST: "GetRequest-PDU"}


# ---------------------------------------------------------------- encoding

def enc_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + enc_length(len(value)) + value


def enc_integer(n: int) -> bytes:
    magnitude = n if n >= 0 else ~n  # -128 fits in one byte, +128 does not
    size = (magnitude.bit_length() + 8) // 8  # +1 bit for the sign
    return tlv(INTEGER, n.to_bytes(size, "big", signed=True))


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
    version = enc_integer(1)  # 0 = v1, 1 = v2c
    return tlv(SEQUENCE, version + tlv(OCTET_STRING, community.encode()) + pdu)


# ---------------------------------------------------------------- decoding

def dec_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first & 0x80:
        n = first & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        length = first
    return tag, data[pos:pos + length], pos + length


def dec_oid(value: bytes) -> str:
    arcs = [value[0] // 40, value[0] % 40]
    arc = 0
    for byte in value[1:]:
        arc = (arc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(arc)
            arc = 0
    return ".".join(map(str, arcs))


def decode(data: bytes):
    """Return a nested (tag name, value) tree."""
    items, pos = [], 0
    while pos < len(data):
        tag, value, pos = dec_tlv(data, pos)
        if tag & 0x20:  # constructed: recurse
            items.append((NAMES.get(tag, hex(tag)), decode(value)))
        elif tag == INTEGER:
            items.append(("INTEGER", int.from_bytes(value, "big", signed=True)))
        elif tag == OCTET_STRING:
            items.append(("OCTET STRING", value.decode("ascii", "replace")))
        elif tag == OID:
            items.append(("OID", dec_oid(value)))
        else:
            items.append((NAMES.get(tag, hex(tag)), value.hex() or None))
    return items


def show(tree, depth: int = 0) -> None:
    for name, value in tree:
        if isinstance(value, list):
            print("  " * depth + name)
            show(value, depth + 1)
        else:
            print("  " * depth + f"{name}: {value}")


def main() -> None:
    packet = get_request("public", 1, ["1.3.6.1.2.1.1.1.0"])
    # The well-known capture of `snmpget -v2c -c public host sysDescr.0` (request-id 1)
    reference = bytes.fromhex("302602010104067075626c6963a019020101020100020100"
                              "300e300c06082b060102010101000500")
    print("sysDescr.0 GetRequest:", packet.hex(" "))
    print("matches reference capture:", packet == reference)

    print()
    packet = get_request("public", 0x1A2B, ["1.3.6.1.2.1.1.3.0", "1.3.6.1.4.1.2021.10.1.3.1"])
    print("two varbinds:", packet.hex(" "))
    show(decode(packet))
    message = decode(packet)[0][1]  # [version, community, pdu]
    pdu = message[2][1]  # [request-id, error-status, error-index, varbind list]
    oids = [varbind[1][0][1] for varbind in pdu[3][1]]
    print("decoded OIDs:", oids)

    print()
    for n in (0, 127, 128, 256, -1, -128, -129):
        print(f"INTEGER {n:>4} -> {enc_integer(n).hex(' ')}")
    print("length 200 ->", enc_length(200).hex(" "), "| length 70000 ->", enc_length(70000).hex(" "))


if __name__ == "__main__":
    main()

# Output:
# sysDescr.0 GetRequest: 30 26 02 01 01 04 06 70 75 62 6c 69 63 a0 19 02 01 01 02 01 00 02 01 00 30 0e 30 0c 06 08 2b 06 01 02 01 01 01 00 05 00
# matches reference capture: True
#
# two varbinds: 30 38 02 01 01 04 06 70 75 62 6c 69 63 a0 2b 02 02 1a 2b 02 01 00 02 01 00 30 1f 30 0c 06 08 2b 06 01 02 01 01 03 00 05 00 30 0f 06 0b 2b 06 01 04 01 8f 65 0a 01 03 01 05 00
# SEQUENCE
#   INTEGER: 1
#   OCTET STRING: public
#   GetRequest-PDU
#     INTEGER: 6699
#     INTEGER: 0
#     INTEGER: 0
#     SEQUENCE
#       SEQUENCE
#         OID: 1.3.6.1.2.1.1.3.0
#         NULL: None
#       SEQUENCE
#         OID: 1.3.6.1.4.1.2021.10.1.3.1
#         NULL: None
# decoded OIDs: ['1.3.6.1.2.1.1.3.0', '1.3.6.1.4.1.2021.10.1.3.1']
#
# INTEGER    0 -> 02 01 00
# INTEGER  127 -> 02 01 7f
# INTEGER  128 -> 02 02 00 80
# INTEGER  256 -> 02 02 01 00
# INTEGER   -1 -> 02 01 ff
# INTEGER -128 -> 02 01 80
# INTEGER -129 -> 02 02 ff 7f
# length 200 -> 81 c8 | length 70000 -> 83 01 11 70
