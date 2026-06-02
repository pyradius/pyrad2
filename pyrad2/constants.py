"""RADIUS protocol constants shared across the package.

Values mirror those defined in the relevant RFCs (RFC 2865, RFC 3576,
RFC 3748, RFC 5176, RFC 5997, RFC 6929).
"""

from enum import IntEnum

# RFC 6929 Extended-Type attribute codes. 241-244 carry a one-byte
# extended-type field; 245-246 add a one-byte flags field whose top bit
# (More) marks an attribute that continues across multiple AVPs.
EXTENDED_ATTRIBUTE_TYPES: frozenset[int] = frozenset({241, 242, 243, 244})
LONG_EXTENDED_ATTRIBUTE_TYPES: frozenset[int] = frozenset({245, 246})
LONG_EXTENDED_MORE_FLAG: int = 0x80

# RFC 6929 §2.3 — Extended-Vendor-Specific. EVS sub-attributes occupy
# extended-type 26 inside an extended (241-244) or long-extended (245-246)
# wrapper and carry a 4-byte vendor-id plus a 1-byte vendor type.
EVS_EXTENDED_TYPE: int = 26


class PacketType(IntEnum):
    """RADIUS packet codes as defined by the IANA registry.

    Used as the ``code`` attribute on every packet — both incoming
    requests dispatched by the server and outgoing replies built with
    ``create_reply_packet``.
    """

    AccessRequest = 1
    AccessAccept = 2
    AccessReject = 3
    AccountingRequest = 4
    AccountingResponse = 5
    AccessChallenge = 11
    StatusServer = 12
    StatusClient = 13
    DisconnectRequest = 40
    DisconnectACK = 41
    DisconnectNAK = 42
    CoARequest = 43
    CoAACK = 44
    CoANAK = 45


class ErrorCause(IntEnum):
    """RFC 5176 Error-Cause attribute values used in CoA/Disconnect NAKs."""

    UnsupportedExtension = 406


class EAPPacketType(IntEnum):
    """EAP packet code field (RFC 3748 §4)."""

    REQUEST = 1
    RESPONSE = 2


class EAPType(IntEnum):
    """EAP method type field (RFC 3748 §5)."""

    IDENTITY = 1


DATATYPES = frozenset(
    [
        "string",
        "ipaddr",
        "integer",
        "date",
        "octets",
        "abinary",
        "ipv6addr",
        "ipv6prefix",
        "short",
        "byte",
        "signed",
        "ifid",
        "ether",
        "tlv",
        "integer64",
        "extended",
        "long-extended",
        "evs",
        # ``vsa`` is FreeRADIUS's parser token for the bare
        # ``Vendor-Specific`` attribute (RFC 2865 code 26). The actual
        # VSA dispatch happens at the packet layer, so for pyrad2's
        # parser the token is functionally equivalent to ``octets`` —
        # accept it so FreeRADIUS dictionaries load cleanly.
        "vsa",
        # ``ipv4prefix`` (RFC 5090) is the IPv4 mirror of ``ipv6prefix``:
        # 1 reserved octet, 1 prefix-length octet, 4 address octets.
        # Accepted at the parser layer so dictionaries declaring it
        # (e.g. ``dictionary.rfc6572``) load. Wire-level encode/decode
        # for it is a separate TODO.
        "ipv4prefix",
        # ``combo-ip`` is FreeRADIUS's "either IPv4 or IPv6, decided at
        # runtime by the on-wire length" type — 4 bytes for IPv4, 16 for
        # IPv6. Wire-level encode/decode lives in ``tools.py``.
        "combo-ip",
    ]
)
