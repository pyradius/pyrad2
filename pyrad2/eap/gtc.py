"""EAP-GTC (RFC 3748 §5.6) — Generic Token Card.

EAP-GTC carries a server-prompted, plaintext password (or token code)
back in an ``EAP-Response``. The wire format is intentionally trivial:

- Server's ``EAP-Request``: code 1 + id + length + type 6 + prompt
  text the operator wants to display to the end user (e.g.
  ``"Password: "``).
- Client's ``EAP-Response``: code 2 + id (echoed) + length + type 6 +
  the plaintext credential.

GTC is rarely used standalone — anything that sends plaintext over a
RADIUS wire is a textbook eavesdropping target. Its everyday role is
as the **inner** method inside an EAP-TLS-protected tunnel
(EAP-PEAP / EAP-TTLS), where the outer TLS handshake provides the
confidentiality GTC itself doesn't. pyrad2 ships the bare method so
those tunnel builders have the leaf to plug in.
"""

import struct
from typing import TYPE_CHECKING

from pyrad2.constants import EAPPacketType
from pyrad2.eap.base import EapMethod
from pyrad2.eap.md5 import (
    EAP_MESSAGE_ATTR,
    STATE_ATTR,
    inject_eap_identity,
    password_from_packet,
)

if TYPE_CHECKING:
    from pyrad2.packet import AuthPacket, Packet

# RFC 3748 IANA assignment.
EAP_TYPE_GTC = 6


def build_eap_gtc_response(eap_id: int, password: bytes) -> bytes:
    """Build an EAP-Response/GTC payload.

    Layout (5-byte header + N-byte data):

    ``code(1) + id(1) + length(2) + type(1) + data(N)``

    where ``length`` is the total payload length including the header.
    """
    return struct.pack(
        "!BBHB%ds" % len(password),
        EAPPacketType.RESPONSE,
        eap_id,
        len(password) + 5,
        EAP_TYPE_GTC,
        password,
    )


def apply_eap_gtc_challenge(pkt: "AuthPacket", reply: "Packet") -> None:
    """Mutate ``pkt`` in place to answer an EAP-GTC prompt.

    Reads the EAP id from the server's ``EAP-Request/GTC`` so the
    response echoes it (RFC 3748 §4.2 requires the id to round-trip),
    then writes the password back as the GTC ``data`` field. The
    prompt text after the header is ignored — pyrad2 doesn't surface
    it because the client already has the credential to send.
    """
    eap_payload = reply[EAP_MESSAGE_ATTR][0]
    if len(eap_payload) < 5:
        raise ValueError(
            f"EAP-GTC challenge header truncated: got {len(eap_payload)} bytes, need at least 5"
        )
    eap_id = eap_payload[1]
    password = password_from_packet(pkt)
    pkt[EAP_MESSAGE_ATTR] = [build_eap_gtc_response(eap_id, password)]
    pkt[STATE_ATTR] = reply[STATE_ATTR]


class GtcMethod(EapMethod):
    """EAP-GTC plaintext-token method.

    Stateless. ``start`` reuses the shared EAP-Identity helper so the
    initial Access-Request looks identical to every other EAP method
    pyrad2 ships; ``respond`` handles the one round of GTC traffic.
    """

    def start(self, pkt) -> None:
        inject_eap_identity(pkt)

    def respond(self, pkt, challenge) -> None:
        apply_eap_gtc_challenge(pkt, challenge)
