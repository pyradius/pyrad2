import binascii
import ssl
import struct
from asyncio import StreamReader
from collections.abc import Buffer
from hashlib import sha256
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_network,
    ip_address,
)


def encode_string(origstr: str) -> bytes:
    """Encode a string to bytes, ensuring it is UTF-8 encoded."""
    if origstr is None:
        return b""
    if len(origstr) > 253:
        raise ValueError("Can only encode strings of <= 253 characters")
    if isinstance(origstr, str):
        return origstr.encode("utf-8")
    else:
        return origstr


def encode_octets(octetstring: str) -> str | bytes:
    """Encode raw octet string (already in bytes).

    Length-capping is the AVP layer's job — fragmenting attributes
    (``concat``, RFC 6929 ``long-extended``, RFC 5904 WiMAX
    continuation) legitimately encode logical values larger than one
    AVP's 253-byte payload field. This function only ensures the
    string-form ``0x...`` hex input doesn't expand past what the AVP
    layer can handle in one shot.
    """
    if octetstring is None:
        return b""

    hexstring: str | bytes
    encoded_octets: str | bytes
    if isinstance(octetstring, bytes) and octetstring.startswith(b"0x"):
        hexstring = octetstring.split(b"0x")[1]
        encoded_octets = binascii.unhexlify(hexstring)
    elif isinstance(octetstring, str) and octetstring.startswith("0x"):
        hexstring = octetstring.split("0x")[1]
        encoded_octets = binascii.unhexlify(hexstring)
    elif isinstance(octetstring, str) and octetstring.isdecimal():
        encoded_octets = struct.pack(">L", int(octetstring)).lstrip(b"\x00")
    else:
        encoded_octets = octetstring

    # Hex literals (``0x...``) historically bounded to one AVP. Raw
    # bytes and decimal forms are trusted: the AVP / fragmentation
    # layer that calls us decides whether to chunk.
    if isinstance(octetstring, (str, bytes)) and (
        (isinstance(octetstring, bytes) and octetstring.startswith(b"0x"))
        or (isinstance(octetstring, str) and octetstring.startswith("0x"))
    ):
        if len(encoded_octets) > 253:
            raise ValueError("Can only encode strings of <= 253 characters")

    return encoded_octets


def encode_address(addr: str) -> bytes:
    """Encode an IPv4 address (dotted string) to 4-byte format."""
    if not isinstance(addr, str):
        raise TypeError("Address has to be a string")
    return IPv4Address(addr).packed


def encode_ipv6_prefix(addr: str, default_prefixlen: int = 128) -> bytes:
    """Encode an IPv6 address and prefix length to 18-byte format."""
    if isinstance(addr, IPv6Network):
        net = addr
    elif isinstance(addr, IPv6Address):
        net = IPv6Network((addr, default_prefixlen), strict=False)
    elif isinstance(addr, str):
        if "/" in addr:
            net = ip_network(addr, strict=False)
        else:
            net = IPv6Network((IPv6Address(addr), default_prefixlen), strict=False)
    elif hasattr(addr, "ip") and hasattr(addr, "prefixlen"):  # netaddr
        return struct.pack("2B", int(addr.prefixlen)) + addr.value.packed
    else:
        raise TypeError(
            "IPv6 Prefix has to be a string, IPv6Network, IPv6Address, or netaddr IPNetwork"
        )

    if getattr(net, "version", None) != 6:
        raise ValueError("not an IPv6 prefix")

    return struct.pack("2B", *[0, net.prefixlen]) + net.network_address.packed


def encode_ipv6_address(addr: str | IPv6Address) -> bytes:
    """Encode an IPv6 address (as string) to 16-byte format."""
    if isinstance(addr, IPv6Address):
        return addr.packed

    if not isinstance(addr, str):
        raise TypeError("IPv6 Address has to be a string")

    return IPv6Address(addr).packed


def encode_combo_ip(addr: str | IPv4Address | IPv6Address) -> bytes:
    """Encode an IPv4 or IPv6 address for a ``combo-ip`` attribute.

    FreeRADIUS's ``combo-ip`` type carries either an IPv4 (4 bytes) or
    an IPv6 (16 bytes) address — the wire length tells which. The
    address family is decided here by inspecting the input: a string is
    parsed by ``ip_address``, which returns the right family natively.
    """

    if isinstance(addr, (IPv4Address, IPv6Address)):
        return addr.packed
    if not isinstance(addr, str):
        raise TypeError("combo-ip has to be a string, IPv4Address, or IPv6Address")
    return ip_address(addr).packed


def encode_ifid(value: str | bytes) -> bytes:
    """Encode an 8-byte Interface-Id (RFC 3162) from ``xxxx:xxxx:xxxx:xxxx`` form.

    Bytes already of length 8 are passed through unchanged so that dictionary
    VALUE entries — which arrive pre-encoded — round-trip cleanly.
    """
    if isinstance(value, (bytes, bytearray)):
        if len(value) != 8:
            raise ValueError("Interface-Id must be 8 bytes")
        return bytes(value)
    if not isinstance(value, str):
        raise TypeError("Interface-Id must be a string")
    groups = value.split(":")
    if len(groups) != 4:
        raise ValueError("Interface-Id must have four colon-separated 16-bit groups")
    try:
        packed = b"".join(int(g, 16).to_bytes(2, "big") for g in groups)
    except (ValueError, OverflowError) as exc:
        raise ValueError("Interface-Id groups must be 16-bit hex") from exc
    return packed


def decode_ifid(value: bytes) -> str:
    """Decode 8-byte Interface-Id (RFC 3162) into ``xxxx:xxxx:xxxx:xxxx`` form."""
    if len(value) != 8:
        raise ValueError("Interface-Id must be 8 bytes")
    return ":".join(
        f"{int.from_bytes(value[i : i + 2], 'big'):04x}" for i in range(0, 8, 2)
    )


def encode_ether(value: str | bytes) -> bytes:
    """Encode a 6-byte Ethernet MAC address from ``hh:hh:hh:hh:hh:hh`` form.

    Accepts both colon and hyphen separators. Bytes of length 6 pass through.
    """
    if isinstance(value, (bytes, bytearray)):
        if len(value) != 6:
            raise ValueError("Ethernet address must be 6 bytes")
        return bytes(value)
    if not isinstance(value, str):
        raise TypeError("Ethernet address must be a string")
    parts = value.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError("Ethernet address must have six octets")
    try:
        return bytes(int(b, 16) for b in parts)
    except ValueError as exc:
        raise ValueError("Ethernet address octets must be hex bytes") from exc


def decode_ether(value: bytes) -> str:
    """Decode a 6-byte Ethernet MAC address into ``hh:hh:hh:hh:hh:hh`` form."""
    if len(value) != 6:
        raise ValueError("Ethernet address must be 6 bytes")
    return ":".join(f"{b:02x}" for b in value)


def encode_ascend_binary(orig_str: str) -> bytes:
    """Encode binary data in Ascend-specific format (length prefixed)."""
    """
    Format: List of type=value pairs separated by spaces.

    Example: 'family=ipv4 action=discard direction=in dst=10.10.255.254/32'

    Note: redirect(0x20) action is added for http-redirect (walled garden) use case

    Type:
        family      ipv4(default) or ipv6
        action      discard(default) or accept or redirect
        direction   in(default) or out
        src         source prefix (default ignore)
        dst         destination prefix (default ignore)
        proto       protocol number / next-header number (default ignore)
        sport       source port (default ignore)
        dport       destination port (default ignore)
        sportq      source port qualifier (default 0)
        dportq      destination port qualifier (default 0)

    Source/Destination Port Qualifier:
        0   no compare
        1   less than
        2   equal to
        3   greater than
        4   not equal to
    """

    terms = {
        "family": b"\x01",
        "action": b"\x00",
        "direction": b"\x01",
        "src": b"\x00\x00\x00\x00",
        "dst": b"\x00\x00\x00\x00",
        "srcl": b"\x00",
        "dstl": b"\x00",
        "proto": b"\x00",
        "sport": b"\x00\x00",
        "dport": b"\x00\x00",
        "sportq": b"\x00",
        "dportq": b"\x00",
    }

    family = "ipv4"
    ip: IPv4Network | IPv6Network

    if orig_str.strip() == "delete":
        return 8 * b"\x00"

    for t in orig_str.split(" "):
        key, value = t.split("=")
        if key == "family" and value == "ipv6":
            family = "ipv6"
            terms[key] = b"\x03"
            if terms["src"] == b"\x00\x00\x00\x00":
                terms["src"] = 16 * b"\x00"
            if terms["dst"] == b"\x00\x00\x00\x00":
                terms["dst"] = 16 * b"\x00"
        elif key == "action" and value == "accept":
            terms[key] = b"\x01"
        elif key == "action" and value == "redirect":
            terms[key] = b"\x20"
        elif key == "direction" and value == "out":
            terms[key] = b"\x00"
        elif key == "src" or key == "dst":
            if family == "ipv4":
                ip = IPv4Network(value)
            else:
                ip = IPv6Network(value)
            terms[key] = ip.network_address.packed
            terms[key + "l"] = struct.pack("B", ip.prefixlen)
        elif key == "sport" or key == "dport":
            terms[key] = struct.pack("!H", int(value))
        elif key == "sportq" or key == "dportq" or key == "proto":
            terms[key] = struct.pack("B", int(value))

    trailer = 8 * b"\x00"

    return b"".join(
        (
            terms["family"],
            terms["action"],
            terms["direction"],
            b"\x00",
            terms["src"],
            terms["dst"],
            terms["srcl"],
            terms["dstl"],
            terms["proto"],
            b"\x00",
            terms["sport"],
            terms["dport"],
            terms["sportq"],
            terms["dportq"],
            b"\x00\x00",
            trailer,
        )
    )


def encode_integer(num: int, format: str = "!I") -> bytes:
    """Encode a 32-bit unsigned integer to 4-byte big-endian."""
    try:
        num = int(num)
    except (ValueError, TypeError):
        raise TypeError("Can not encode non-integer as integer")
    return struct.pack(format, num)


def encode_integer64(num: int, format: str = "!Q") -> bytes:
    """Encode a 64-bit unsigned integer to 8-byte big-endian."""
    try:
        num = int(num)
    except (ValueError, TypeError):
        raise TypeError("Can not encode non-integer as integer64")
    return struct.pack(format, num)


def encode_date(num: int) -> bytes:
    """Encode a UNIX timestamp (int) to 4-byte format."""
    if not isinstance(num, int):
        raise TypeError("Can not encode non-integer as date")
    return struct.pack("!I", num)


def decode_string(orig_str: bytes) -> str:
    """Decode UTF-8 bytes into a string."""
    try:
        return orig_str.decode("utf-8")
    except UnicodeDecodeError:
        # Non-UTF-8 data displayed in hexadecimal form
        return orig_str.hex()


def decode_octets(orig_bytes: bytes) -> bytes:
    """Return bytes unchanged (octet format)."""
    return orig_bytes


def decode_address(addr: str) -> str:
    """Decode 4-byte data into an IPv4 dotted string."""
    return str(ip_address(addr))


def decode_ipv6_prefix(addr: bytes | bytearray) -> str:
    """Decode 18-byte IPv6 prefix format into address/prefix tuple."""
    # RADIUS IPv6-Prefix is: 2 bytes (reserved, prefixlen) + prefix bytes (0..16)
    addr = addr + b"\x00" * (18 - len(addr))
    _, length = struct.unpack("!BB", addr[:2])
    prefix_bytes = addr[2:18]
    prefix = IPv6Address(prefix_bytes)
    return str(IPv6Network((prefix, int(length)), strict=False))


def decode_ipv6_address(addr: bytes | bytearray) -> str:
    """Decode 16-byte IPv6 address into a readable string."""
    # RADIUS IPv6-Prefix is: 2 bytes (reserved, prefixlen) + prefix bytes (0..16)
    addr = addr + b"\x00" * (16 - len(addr))
    return str(IPv6Address(addr))


def decode_combo_ip(addr: bytes | bytearray) -> str:
    """Decode a ``combo-ip`` attribute, dispatching on wire length.

    4 bytes is an IPv4 address; 16 bytes an IPv6 address. Any other
    length is invalid — combo-ip has no other valid encoding.
    """

    if len(addr) == 4:
        return str(IPv4Address(bytes(addr)))
    if len(addr) == 16:
        return str(IPv6Address(bytes(addr)))
    raise ValueError(
        f"combo-ip value must be 4 (IPv4) or 16 (IPv6) bytes, got {len(addr)}"
    )


def decode_ascend_binary(orig_bytes: bytes) -> bytes:
    """Decode Ascend-specific binary format (length-prefixed)."""
    return orig_bytes


def decode_integer(num: Buffer, format: str = "!I") -> bytes:
    """Decode 4-byte big-endian unsigned integer."""
    return struct.unpack(format, num)[0]


def decode_integer64(num: Buffer, format: str = "!Q") -> bytes:
    """Decode 8-byte big-endian unsigned integer."""
    return struct.unpack(format, num)[0]


def decode_date(num: Buffer) -> bytes:
    """Decode 4-byte UNIX timestamp into an integer."""
    return (struct.unpack("!I", num))[0]


def encode_attr(datatype: str, value) -> bytes | str:
    """Encode a RADIUS attribute (type, value, length) into bytes."""
    if datatype == "string":
        return encode_string(value)
    elif datatype == "octets":
        return encode_octets(value)
    elif datatype == "integer":
        return encode_integer(value)
    elif datatype == "ipaddr":
        return encode_address(value)
    elif datatype == "ipv6prefix":
        return encode_ipv6_prefix(value)
    elif datatype == "ipv6addr":
        return encode_ipv6_address(value)
    elif datatype == "combo-ip":
        return encode_combo_ip(value)
    elif datatype == "abinary":
        return encode_ascend_binary(value)
    elif datatype == "signed":
        return encode_integer(value, "!i")
    elif datatype == "short":
        return encode_integer(value, "!H")
    elif datatype == "byte":
        return encode_integer(value, "!B")
    elif datatype == "date":
        return encode_date(value)
    elif datatype == "integer64":
        return encode_integer64(value)
    elif datatype == "ifid":
        return encode_ifid(value)
    elif datatype == "ether":
        return encode_ether(value)
    else:
        raise ValueError("Unknown attribute type %s" % datatype)


def decode_attr(datatype: str, value) -> bytes | str:
    """Decode a RADIUS attribute from bytes into a type and value."""
    if datatype == "string":
        return decode_string(value)
    elif datatype == "octets":
        return decode_octets(value)
    elif datatype == "integer":
        return decode_integer(value)
    elif datatype == "ipaddr":
        return decode_address(value)
    elif datatype == "ipv6prefix":
        return decode_ipv6_prefix(value)
    elif datatype == "ipv6addr":
        return decode_ipv6_address(value)
    elif datatype == "combo-ip":
        return decode_combo_ip(value)
    elif datatype == "abinary":
        return decode_ascend_binary(value)
    elif datatype == "signed":
        return decode_integer(value, "!i")
    elif datatype == "short":
        return decode_integer(value, "!H")
    elif datatype == "byte":
        return decode_integer(value, "!B")
    elif datatype == "date":
        return decode_date(value)
    elif datatype == "integer64":
        return decode_integer64(value)
    elif datatype == "ifid":
        return decode_ifid(value)
    elif datatype == "ether":
        return decode_ether(value)
    else:
        raise ValueError("Unknown attribute type %s" % datatype)


def get_cert_fingerprint(cert: bytes) -> str:
    """Generate SHA-256 fingerprint from a certificate."""
    der_bytes = ssl.PEM_cert_to_DER_cert(ssl.DER_cert_to_PEM_cert(cert))
    hash = sha256(der_bytes).digest()
    # Return in base64 or hex
    return hash.hex()  # or base64.b64encode(sha256).decode()


def normalize_cert_fingerprint(fingerprint: str) -> str:
    """Normalize a SHA-256 certificate fingerprint for comparison.

    Accepts plain hex, colon-separated hex, and values prefixed with
    `sha256:`. Raises ValueError when the normalized value is not a 64
    character hexadecimal SHA-256 fingerprint.
    """
    normalized = (
        fingerprint.lower().removeprefix("sha256:").replace(":", "").replace(" ", "")
    )
    if len(normalized) != 64:
        raise ValueError("SHA-256 certificate fingerprints must be 64 hex characters")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError("Certificate fingerprints must be hexadecimal") from exc
    return normalized


def cert_fingerprint_matches(cert: bytes, allowed_fingerprints: set[str]) -> bool:
    """Return True when a DER certificate's SHA-256 fingerprint is allowed."""
    return get_cert_fingerprint(cert) in allowed_fingerprints


async def read_radius_packet(reader: StreamReader) -> bytes:
    """Read a full RADIUS packet from the stream.

    There's no built-in framing in RadSec, so we can't read a fixed-size packet.
    Instead, we read the header first to determine the length of the packet,
    and then read the rest of the packet based on that length.

    RADIUS packets are prefixed with a 4-byte header:
        - Code (1 byte)
        - Identifier (1 byte)
        - Length (2 bytes)

    The length includes the header, so the minimum length is 20 bytes
    (4-byte header + 16-byte Authenticator).
    If the length is less than 20, it is considered invalid.

    :param reader: asyncio StreamReader to read from
    :return: Full RADIUS packet as bytes
    """
    header = await reader.readexactly(4)
    code, identifier, length = struct.unpack("!BBH", header)

    if length < 20:
        raise ValueError("Invalid RADIUS packet length")

    body = await reader.readexactly(length - 4)
    return header + body
