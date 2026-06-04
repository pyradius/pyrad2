"""Tests for the EAP-MSCHAPv2 method.

The method drives a two-round exchange (Challenge → Response →
Success-Request → Success-Response) so each round is unpacked here in
isolation. The Challenge-decoding test uses the RFC 2759 §D inputs
fed back through the EAP wrapper so the bytes coming out of
``_build_response`` match the documented vector — the same inputs the
``test_mschap.py`` suite pins for the bare primitives.
"""

import struct

import pytest

from pyrad2 import eap
from pyrad2.constants import EAPPacketType
from pyrad2.eap.mschapv2 import (
    EAP_TYPE_MSCHAPV2,
    MschapV2Method,
    OP_CHALLENGE,
    OP_FAILURE,
    OP_RESPONSE,
    OP_SUCCESS,
)
from pyrad2.exceptions import PacketError

cryptography = pytest.importorskip("cryptography")  # noqa: F841 — extras guard.

# Same vector as ``tests/test_mschap.py``.
RFC_AUTH_CHALLENGE = bytes.fromhex("5B5D7C7D7B3F2F3E3C2C602132262628")
RFC_PEER_CHALLENGE = bytes.fromhex("21402324255E262A28295F2B3A337C7E")
RFC_USER = "User"
RFC_PASSWORD = "clientPass"
RFC_NT_RESPONSE = bytes.fromhex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
RFC_AUTHENTICATOR_RESPONSE = b"S=407A5589115FD0D6209F510FE9C04566932CDA56"


def _build_eap_challenge(
    eap_id: int = 1,
    mschap_id: int = 99,
    authenticator_challenge: bytes = RFC_AUTH_CHALLENGE,
    server_name: bytes = b"radius.example",
) -> bytes:
    """Construct an inbound EAP-Request/MS-CHAP-V2 Challenge payload."""
    ms_length = 1 + 1 + 2 + 1 + 16 + len(server_name)
    eap_length = 5 + ms_length
    return (
        struct.pack(
            "!BBHBB",
            1,  # EAP-Request
            eap_id,
            eap_length,
            EAP_TYPE_MSCHAPV2,
            OP_CHALLENGE,
        )
        + bytes([mschap_id])
        + struct.pack("!H", ms_length)
        + bytes([16])
        + authenticator_challenge
        + server_name
    )


def _build_eap_success_request(
    eap_id: int, message: bytes = RFC_AUTHENTICATOR_RESPONSE + b" M=OK"
) -> bytes:
    ms_length = 1 + 1 + 2 + len(message)
    eap_length = 5 + ms_length
    return (
        struct.pack(
            "!BBHBB",
            1,
            eap_id,
            eap_length,
            EAP_TYPE_MSCHAPV2,
            OP_SUCCESS,
        )
        + bytes([0])  # mschap_id (server's choice; not used by the client)
        + struct.pack("!H", ms_length)
        + message
    )


class TestStart:
    def test_injects_eap_identity_with_username(self):
        # EAP-Identity Response carries the username — RFC 3748 §5.1.
        pkt = {
            eap.USER_PASSWORD_ATTR: [b"clientPass"],
            "User-Name": ["alice"],
        }
        method = MschapV2Method()
        method.start(pkt)

        assert eap.EAP_MESSAGE_ATTR in pkt
        payload = pkt[eap.EAP_MESSAGE_ATTR][0]
        # Layout: code(1)=Response, id(1), length(2), type(1)=Identity, data
        assert payload[0] == EAPPacketType.RESPONSE
        assert payload[4] == 1  # EAP-Type Identity
        assert payload[5:] == b"alice"

    def test_requires_user_name(self):
        pkt = {eap.USER_PASSWORD_ATTR: [b"pw"]}
        with pytest.raises(PacketError, match="User-Name"):
            MschapV2Method().start(pkt)

    def test_requires_user_password(self):
        pkt = {"User-Name": [b"alice"]}
        with pytest.raises(PacketError, match="User-Password"):
            MschapV2Method().start(pkt)


class TestRespondChallenge:
    def _seed(self) -> tuple[MschapV2Method, dict]:
        pkt = {
            eap.USER_PASSWORD_ATTR: [RFC_PASSWORD.encode()],
            "User-Name": [RFC_USER],
        }
        method = MschapV2Method()
        method.start(pkt)
        return method, pkt

    def test_response_packet_layout(self):
        method, pkt = self._seed()
        # Force the peer challenge so the NT-Response matches the
        # RFC vector — the method generates a random one otherwise.
        method._peer_challenge = RFC_PEER_CHALLENGE  # type: ignore[attr-defined]
        # Inject the peer challenge via a deterministic patch of
        # secrets.token_bytes before respond() consumes it.

        challenge = _build_eap_challenge(eap_id=42, mschap_id=7)
        reply = {eap.EAP_MESSAGE_ATTR: [challenge], eap.STATE_ATTR: [b"st"]}

        # The respond() call re-generates _peer_challenge via secrets;
        # to keep the test deterministic, monkey-patch ``secrets.token_bytes``
        # on the module under test.
        import pyrad2.eap.mschapv2 as mschapv2_mod

        original = mschapv2_mod.secrets.token_bytes
        try:
            mschapv2_mod.secrets.token_bytes = lambda n: RFC_PEER_CHALLENGE[:n]
            method.respond(pkt, reply)
        finally:
            mschapv2_mod.secrets.token_bytes = original

        response_payload = pkt[eap.EAP_MESSAGE_ATTR][0]

        # EAP wrapper.
        assert response_payload[0] == EAPPacketType.RESPONSE
        assert response_payload[1] == 42  # EAP id echoed
        assert response_payload[4] == EAP_TYPE_MSCHAPV2
        assert response_payload[5] == OP_RESPONSE
        assert response_payload[6] == 7  # MS-CHAPv2-Id echoed
        assert response_payload[9] == 49  # Value-Size
        # 49-byte Response payload: peer(16) | reserved(8) | nt(24) | flags(1)
        assert response_payload[10:26] == RFC_PEER_CHALLENGE
        assert response_payload[26:34] == b"\x00" * 8
        assert response_payload[34:58] == RFC_NT_RESPONSE
        assert response_payload[58] == 0  # flags
        # Name appended.
        assert response_payload[59:] == RFC_USER.encode()

        # State must carry across.
        assert pkt[eap.STATE_ATTR] == [b"st"]

    def test_rejects_wrong_eap_type(self):
        method, pkt = self._seed()
        # type byte 4 (MD5) — wrong for an MSCHAPv2 method.
        bogus = struct.pack("!BBHBB", 1, 0, 6, 4, OP_CHALLENGE)
        reply = {eap.EAP_MESSAGE_ATTR: [bogus], eap.STATE_ATTR: [b""]}
        with pytest.raises(ValueError, match="MS-CHAPv2"):
            method.respond(pkt, reply)

    def test_rejects_unknown_opcode(self):
        method, pkt = self._seed()
        bogus = struct.pack("!BBHBB", 1, 0, 6, EAP_TYPE_MSCHAPV2, 99)
        reply = {eap.EAP_MESSAGE_ATTR: [bogus], eap.STATE_ATTR: [b""]}
        with pytest.raises(ValueError, match="OpCode 99"):
            method.respond(pkt, reply)


class TestRespondSuccess:
    def _drive_to_success(self) -> tuple[MschapV2Method, dict, int]:
        pkt = {
            eap.USER_PASSWORD_ATTR: [RFC_PASSWORD.encode()],
            "User-Name": [RFC_USER],
        }
        method = MschapV2Method()
        method.start(pkt)

        # Seed deterministic peer challenge so the stored NT-Response
        # matches RFC_NT_RESPONSE.
        import pyrad2.eap.mschapv2 as mschapv2_mod

        original = mschapv2_mod.secrets.token_bytes
        try:
            mschapv2_mod.secrets.token_bytes = lambda n: RFC_PEER_CHALLENGE[:n]
            challenge_payload = _build_eap_challenge(eap_id=1, mschap_id=10)
            method.respond(
                pkt,
                {eap.EAP_MESSAGE_ATTR: [challenge_payload], eap.STATE_ATTR: [b"s"]},
            )
        finally:
            mschapv2_mod.secrets.token_bytes = original
        return method, pkt, 1

    def test_acks_a_valid_success_request(self):
        method, pkt, _ = self._drive_to_success()
        success = _build_eap_success_request(eap_id=2)
        reply = {eap.EAP_MESSAGE_ATTR: [success], eap.STATE_ATTR: [b"s"]}

        method.respond(pkt, reply)

        ack = pkt[eap.EAP_MESSAGE_ATTR][0]
        assert ack[0] == EAPPacketType.RESPONSE
        assert ack[1] == 2  # echoed EAP id
        assert ack[4] == EAP_TYPE_MSCHAPV2
        assert ack[5] == OP_SUCCESS
        assert len(ack) == 6

    def test_rejects_bad_authenticator_response(self):
        method, pkt, _ = self._drive_to_success()
        bad_message = b"S=" + b"00" * 20 + b" M=fake"
        success = _build_eap_success_request(eap_id=2, message=bad_message)
        reply = {eap.EAP_MESSAGE_ATTR: [success], eap.STATE_ATTR: [b"s"]}

        with pytest.raises(ValueError, match="Authenticator Response"):
            method.respond(pkt, reply)


class TestRespondFailure:
    def test_emits_bare_failure_ack(self):
        pkt = {
            eap.USER_PASSWORD_ATTR: [b"pw"],
            "User-Name": [b"u"],
        }
        method = MschapV2Method()
        method.start(pkt)

        failure_payload = struct.pack("!BBHBB", 1, 8, 6, EAP_TYPE_MSCHAPV2, OP_FAILURE)
        reply = {
            eap.EAP_MESSAGE_ATTR: [failure_payload],
            eap.STATE_ATTR: [b""],
        }
        method.respond(pkt, reply)

        ack = pkt[eap.EAP_MESSAGE_ATTR][0]
        assert ack == struct.pack("!BBHBB", 2, 8, 6, EAP_TYPE_MSCHAPV2, OP_FAILURE)


class TestRegistryWiring:
    def test_registered_under_canonical_name(self):
        assert isinstance(eap.get_method("eap-mschapv2"), MschapV2Method)

    def test_each_lookup_returns_a_fresh_instance(self):
        # Stateful method — concurrent conversations must not share state.
        a = eap.get_method("eap-mschapv2")
        b = eap.get_method("eap-mschapv2")
        assert a is not b
