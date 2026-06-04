"""EAP-MSCHAPv2 method (RFC 2759 + draft-kamath-pppext-eap-mschapv2).

Wraps the MS-CHAPv2 primitives from ``pyrad2.mschap`` in the EAP
framing every RADIUS-EAP client expects. The flow is two rounds after
the initial Identity exchange:

1. Server → ``Access-Challenge`` carrying EAP-Request / MS-CHAPv2
   **Challenge** (OpCode 1) with a 16-byte authenticator challenge and
   the server's name.
2. Client → ``Access-Request`` carrying EAP-Response / MS-CHAPv2
   **Response** (OpCode 2) with a fresh peer challenge and the
   24-byte NT-Response.
3. Server → ``Access-Challenge`` carrying EAP-Request / MS-CHAPv2
   **Success** (OpCode 3) with ``"S=<auth> M=<msg>"``.
4. Client → ``Access-Request`` carrying EAP-Response / MS-CHAPv2
   **Success** (OpCode 3, six-byte header only) to acknowledge.
5. Server → ``Access-Accept``.

The method instance is **stateful** — it remembers the peer challenge
and NT-Response across rounds so it can verify the server's
Authenticator Response in step 3. ``pyrad2.eap.register_method``
registers the class as a factory so each conversation gets its own
instance and two concurrent EAP-MSCHAPv2 clients can't trample on
each other's state.

Requires ``pip install pyrad2[mschap]`` for the DES primitive used
inside ``pyrad2.mschap``.
"""

import secrets
import struct
from typing import TYPE_CHECKING

from pyrad2.constants import EAPPacketType, EAPType
from pyrad2.eap.base import EapMethod
from pyrad2.eap.md5 import EAP_MESSAGE_ATTR, STATE_ATTR, password_from_packet
from pyrad2.exceptions import PacketError
from pyrad2.mschap import (
    generate_nt_response,
    verify_authenticator_response,
)

if TYPE_CHECKING:
    from pyrad2.packet import AuthPacket, Packet

# IANA / draft-kamath assignments.
EAP_TYPE_MSCHAPV2 = 26

OP_CHALLENGE = 1
OP_RESPONSE = 2
OP_SUCCESS = 3
OP_FAILURE = 4

USER_NAME_ATTR = 1


def _build_eap_identity_with_name(identity: bytes) -> bytes:
    """Build an EAP-Identity Response carrying the supplied identity.

    Mirrors ``pyrad2.eap.md5.build_eap_identity`` but takes the
    *identity* (typically the username) explicitly. RFC 3748 §5.1
    requires the EAP-Identity Response to carry the user's identity,
    not their credential; the long-standing pyrad2 helper for EAP-MD5
    uses ``User-Password`` for backwards-compat reasons we preserve in
    that method but don't propagate here.
    """
    # Local import keeps the cycle out of module load order.
    from pyrad2 import packet

    return struct.pack(
        "!BBHB%ds" % len(identity),
        EAPPacketType.RESPONSE,
        packet.CURRENT_ID,
        len(identity) + 5,
        EAPType.IDENTITY,
        identity,
    )


def _user_name_from_packet(pkt) -> bytes:
    """Extract the bare User-Name for use in EAP-Identity and ChallengeHash.

    EAP-MSCHAPv2 always needs the username — it goes into the identity
    response, the inner ``ChallengeHash`` SHA-1, and the response's
    trailing ``Name`` field. Raising here gives a clean error rather
    than a downstream ``KeyError``.
    """
    if USER_NAME_ATTR not in pkt and "User-Name" not in pkt:
        raise PacketError("EAP-MSCHAPv2 requires a User-Name attribute on the packet")
    raw = pkt[USER_NAME_ATTR][0] if USER_NAME_ATTR in pkt else pkt["User-Name"][0]
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return raw


class MschapV2Method(EapMethod):
    """EAP-MSCHAPv2 driver, stateful per conversation.

    Carries the authenticator challenge, peer challenge, and computed
    NT-Response across the Challenge → Response → Success rounds so
    the Authenticator Response check on the final Success-Request can
    use the same inputs the Response was built from.
    """

    def __init__(self) -> None:
        self._user_name: bytes = b""
        # ``_password`` is stored as ``str`` because MS-CHAPv2's NT
        # Password Hash is MD4 over the password in *UTF-16LE*
        # (RFC 2759 §8.3). RADIUS attributes are raw bytes — we decode
        # them to a string so ``mschap.nt_password_hash`` does the
        # UTF-16LE conversion itself instead of double-encoding.
        self._password: str = ""
        self._authenticator_challenge: bytes = b""
        self._peer_challenge: bytes = b""
        self._nt_response: bytes = b""

    def start(self, pkt: "AuthPacket") -> None:
        self._user_name = _user_name_from_packet(pkt)
        raw_password = password_from_packet(pkt)
        # User-Password lands here as UTF-8 bytes from the typical
        # ``User_Password="..."`` kwarg path. Decode strictly: bytes
        # that aren't a legal UTF-8 sequence would silently produce
        # the wrong hash if we fell back to raw passthrough.
        self._password = raw_password.decode("utf-8")
        pkt[EAP_MESSAGE_ATTR] = [_build_eap_identity_with_name(self._user_name)]

    def respond(self, pkt: "AuthPacket", challenge: "Packet") -> None:
        eap_payload = challenge[EAP_MESSAGE_ATTR][0]
        if len(eap_payload) < 6:
            raise ValueError(
                f"EAP-MSCHAPv2 header truncated: got {len(eap_payload)} bytes, need at least 6"
            )
        eap_id = eap_payload[1]
        eap_type = eap_payload[4]
        if eap_type != EAP_TYPE_MSCHAPV2:
            raise ValueError(
                f"Expected EAP-Type {EAP_TYPE_MSCHAPV2} (MS-CHAPv2), got {eap_type}"
            )
        op_code = eap_payload[5]

        if op_code == OP_CHALLENGE:
            response_payload = self._build_response(eap_id, eap_payload)
        elif op_code == OP_SUCCESS:
            response_payload = self._build_success_response(eap_id, eap_payload)
        elif op_code == OP_FAILURE:
            response_payload = self._build_failure_response(eap_id)
        else:
            raise ValueError(f"Unknown EAP-MSCHAPv2 OpCode {op_code}")

        pkt[EAP_MESSAGE_ATTR] = [response_payload]
        # State must carry across every round of a multi-challenge EAP
        # session — without it the server has no way to correlate.
        pkt[STATE_ATTR] = challenge[STATE_ATTR]

    def _build_response(self, eap_id: int, challenge_payload: bytes) -> bytes:
        """Parse OpCode 1 (Challenge) and build OpCode 2 (Response).

        Inbound wire (draft-kamath §3.2.1)::

            code(1) | id(1) | length(2) | type(1) | OpCode=1(1)
            | MS-CHAPv2-Id(1) | MS-Length(2) | Value-Size=16(1)
            | Challenge(16) | Name(variable)

        The Name field is informational — pyrad2 ignores it on the
        wire and uses the local ``User-Name`` for the ChallengeHash
        computation per RFC 2759.
        """
        if len(challenge_payload) < 26:
            raise ValueError(
                f"EAP-MSCHAPv2 Challenge body truncated: got {len(challenge_payload)} bytes, need at least 26"
            )
        mschap_id = challenge_payload[6]
        value_size = challenge_payload[9]
        if value_size != 16:
            raise ValueError(
                f"EAP-MSCHAPv2 Challenge Value-Size must be 16, got {value_size}"
            )
        self._authenticator_challenge = challenge_payload[10:26]
        self._peer_challenge = secrets.token_bytes(16)
        self._nt_response = generate_nt_response(
            self._authenticator_challenge,
            self._peer_challenge,
            self._user_name,
            self._password,
        )

        # 49-byte Response value: Peer-Challenge(16) | Reserved(8) | NT-Response(24) | Flags(1).
        response_value = (
            self._peer_challenge + b"\x00" * 8 + self._nt_response + b"\x00"
        )

        # MS-Length spans from OpCode through the end of Name.
        ms_length = 1 + 1 + 2 + 1 + 49 + len(self._user_name)
        eap_length = 5 + ms_length

        header = struct.pack(
            "!BBHBB",
            EAPPacketType.RESPONSE,
            eap_id,
            eap_length,
            EAP_TYPE_MSCHAPV2,
            OP_RESPONSE,
        )
        return (
            header
            + bytes([mschap_id])
            + struct.pack("!H", ms_length)
            + bytes([49])
            + response_value
            + self._user_name
        )

    def _build_success_response(self, eap_id: int, success_payload: bytes) -> bytes:
        """Verify the server's Authenticator Response and ACK with OpCode 3.

        The server's Success message body is ``"S=<40 hex> M=<text>"``
        (RFC 2548 §2.3.3). When present, we recompute the expected
        ``S=...`` from the stored NT-Response inputs and refuse to
        ACK if it doesn't match — that's the mutual-auth part of
        MS-CHAPv2.
        """
        message = success_payload[6:] if len(success_payload) > 6 else b""
        if message and b"S=" in message:
            if not verify_authenticator_response(
                self._password,
                self._nt_response,
                self._peer_challenge,
                self._authenticator_challenge,
                self._user_name,
                message,
            ):
                raise ValueError(
                    "EAP-MSCHAPv2 server Authenticator Response failed verification"
                )
        # Six-byte ACK: EAP header (5) + OpCode (1). No payload.
        return struct.pack(
            "!BBHBB",
            EAPPacketType.RESPONSE,
            eap_id,
            6,
            EAP_TYPE_MSCHAPV2,
            OP_SUCCESS,
        )

    def _build_failure_response(self, eap_id: int) -> bytes:
        """ACK a server-reported failure so the EAP session closes cleanly.

        After a Failure-Request the server will send Access-Reject;
        the bare Failure-Response keeps the EAP framing well-formed so
        downstream logging picks up the explicit ``OpCode == 4``
        rather than a transport-level oddity.
        """
        return struct.pack(
            "!BBHBB",
            EAPPacketType.RESPONSE,
            eap_id,
            6,
            EAP_TYPE_MSCHAPV2,
            OP_FAILURE,
        )
