"""EAP byte-packing helpers shared by sync and async RADIUS clients.

Currently covers the EAP-MD5 challenge/response flow defined in
RFC 3748 §5.4. The helpers operate on raw ``bytes`` so they can be
called from both the synchronous ``Client`` and the asyncio
``ClientAsync`` without dragging packet objects through the helper.
"""

__docformat__ = "epytext en"

import hashlib
import struct

from pyrad2 import packet
from pyrad2.constants import EAPPacketType, EAPType
from pyrad2.exceptions import PacketError

# RFC 2865 attribute codes used by the EAP-MD5 flow.
EAP_MESSAGE_ATTR = 79
STATE_ATTR = 24
USER_PASSWORD_ATTR = 2
USER_NAME_ATTR = 1


def build_eap_identity(password: bytes) -> bytes:
    """Build an EAP-Identity Response payload from a password.

    Matches the sync client's historic behaviour: the EAP identifier is
    taken from the module-level ``packet.CURRENT_ID`` rolling counter.
    """
    return struct.pack(
        "!BBHB%ds" % len(password),
        EAPPacketType.RESPONSE,
        packet.CURRENT_ID,
        len(password) + 5,
        EAPType.IDENTITY,
        password,
    )


def build_eap_md5_challenge(eap_id: int, password: bytes, eap_md5: bytes) -> bytes:
    """Build an EAP-Type-MD5-Challenge response payload.

    Args:
        eap_id: EAP identifier copied from the Access-Challenge.
        password: User password (used as the MD5 secret).
        eap_md5: Raw EAP-MD5 attribute payload from the challenge,
            starting with the length-prefix byte the server sent.
    """
    md5_challenge = hashlib.md5(
        struct.pack("!B", eap_id) + password + eap_md5[1:]
    ).digest()
    return (
        struct.pack(
            "!BBHBB",
            EAPPacketType.RESPONSE,
            eap_id,
            len(md5_challenge) + 6,
            4,
            len(md5_challenge),
        )
        + md5_challenge
    )


def password_from_packet(pkt) -> bytes:
    """Extract the user password from an AuthPacket for EAP framing.

    Raises ``PacketError`` if no ``User-Password`` is present. The
    legacy fall-back to ``User-Name`` silently mis-keyed the EAP-MD5
    challenge with the username, downgrading authentication to a value
    that anyone observing the request could reproduce.
    """
    if USER_PASSWORD_ATTR not in pkt:
        raise PacketError(
            "EAP framing requires a User-Password attribute on the packet"
        )
    return pkt[USER_PASSWORD_ATTR][0]


def inject_eap_identity(pkt) -> None:
    """Populate the EAP-Message attribute with an EAP-Identity response."""
    pkt[EAP_MESSAGE_ATTR] = [build_eap_identity(password_from_packet(pkt))]


def apply_eap_md5_challenge(pkt, reply) -> None:
    """Mutate ``pkt`` in place to answer an EAP-MD5 Access-Challenge."""
    eap_payload = reply[EAP_MESSAGE_ATTR][0]
    _, eap_id, _, _, eap_md5 = struct.unpack(
        "!BBHB%ds" % (len(eap_payload) - 5), eap_payload
    )
    pkt[EAP_MESSAGE_ATTR] = [
        build_eap_md5_challenge(eap_id, password_from_packet(pkt), eap_md5)
    ]
    # Carry the server's State across the challenge round-trip.
    pkt[STATE_ATTR] = reply[STATE_ATTR]
