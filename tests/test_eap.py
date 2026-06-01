"""Tests for the shared EAP byte-packing helpers.

These cover the public surface of ``pyrad2.eap`` which is exercised by
sync, async, and RadSec clients during EAP-MD5 challenge/response.
Each helper unpacks raw bytes from on-the-wire EAP messages, so the
truncation cases below guard the fixed-width struct unpacks from
silently producing garbage if a malformed payload ever reaches them.
"""

import struct

import pytest

from pyrad2 import eap
from pyrad2.constants import EAPPacketType, EAPType
from pyrad2.exceptions import PacketError


class TestBuildEapIdentity:
    def test_payload_layout_matches_rfc3748(self):
        password = b"hunter2"
        payload = eap.build_eap_identity(password)

        code, _eap_id, length, eap_type = struct.unpack("!BBHB", payload[:5])
        assert code == EAPPacketType.RESPONSE
        assert eap_type == EAPType.IDENTITY
        # length field counts the EAP payload itself (5 header + password).
        assert length == len(password) + 5
        assert payload[5:] == password

    def test_accepts_empty_password(self):
        payload = eap.build_eap_identity(b"")
        # 4 header bytes + 1 type byte = 5 bytes.
        assert len(payload) == 5


class TestBuildEapMd5Challenge:
    def test_payload_layout_matches_rfc3748(self):
        eap_id = 7
        password = b"hunter2"
        # eap_md5 starts with a length-prefix byte then the challenge.
        challenge = b"\x10" + b"\xaa" * 16
        payload = eap.build_eap_md5_challenge(eap_id, password, challenge)

        code, returned_id, length, eap_type, _ = struct.unpack("!BBHBB", payload[:6])
        assert code == EAPPacketType.RESPONSE
        assert returned_id == eap_id
        assert eap_type == 4  # EAP-Type for MD5-Challenge.
        # MD5 always produces 16 bytes; payload is 6-byte header + 16-byte digest.
        assert length == 22
        assert len(payload) == 22

    def test_truncated_challenge_does_not_crash(self):
        """A short eap_md5 still produces a deterministic digest.

        The helper does not validate the inner length-prefix; callers
        are expected to feed it the raw attribute value. Truncation
        merely changes the input to MD5, which must not raise.
        """
        payload = eap.build_eap_md5_challenge(1, b"pw", b"\x00")
        assert len(payload) == 22


class TestPasswordFromPacket:
    def test_prefers_user_password_when_present(self):
        pkt = {eap.USER_PASSWORD_ATTR: [b"pw"], eap.USER_NAME_ATTR: [b"alice"]}
        assert eap.password_from_packet(pkt) == b"pw"

    def test_raises_when_user_password_is_missing(self):
        # Historically this fell back to the User-Name attribute, which
        # silently mis-keyed the EAP-MD5 challenge. The new contract
        # requires User-Password explicitly.
        pkt = {eap.USER_NAME_ATTR: [b"alice"]}
        with pytest.raises(PacketError, match="User-Password"):
            eap.password_from_packet(pkt)

    def test_raises_when_neither_attribute_is_present(self):
        with pytest.raises(PacketError, match="User-Password"):
            eap.password_from_packet({})


class TestInjectEapIdentity:
    def test_populates_eap_message_attribute(self):
        pkt = {eap.USER_PASSWORD_ATTR: [b"hunter2"]}
        eap.inject_eap_identity(pkt)

        assert eap.EAP_MESSAGE_ATTR in pkt
        eap_message = pkt[eap.EAP_MESSAGE_ATTR][0]
        # Response code, Identity type, password trailer.
        assert eap_message[0] == EAPPacketType.RESPONSE
        assert eap_message[4] == EAPType.IDENTITY
        assert eap_message[5:] == b"hunter2"


class TestApplyEapMd5Challenge:
    def _make_challenge_reply(self, eap_id=7, state=b"opaque"):
        md5_value = b"\x10" + b"\xaa" * 16
        eap_payload = (
            b"\x01"  # EAP Request
            + bytes([eap_id])
            + (5 + len(md5_value)).to_bytes(2, "big")
            + b"\x04"  # EAP-MD5 type
            + md5_value
        )
        return {eap.EAP_MESSAGE_ATTR: [eap_payload], eap.STATE_ATTR: [state]}

    def test_replaces_eap_message_and_copies_state(self):
        pkt = {eap.USER_PASSWORD_ATTR: [b"pw"]}
        reply = self._make_challenge_reply(eap_id=7, state=b"opaque-state")

        eap.apply_eap_md5_challenge(pkt, reply)

        assert eap.EAP_MESSAGE_ATTR in pkt
        response = pkt[eap.EAP_MESSAGE_ATTR][0]
        # Mirrors challenge id and uses EAP-Response/EAP-MD5.
        assert response[0] == EAPPacketType.RESPONSE
        assert response[1] == 7
        assert response[4] == 4
        # State must round-trip unchanged.
        assert pkt[eap.STATE_ATTR] == [b"opaque-state"]

    def test_truncated_eap_message_raises_struct_error(self):
        """A reply with <5 bytes of EAP-Message must not silently succeed.

        The helper unpacks a fixed-width header (BBHB = 5 bytes) and
        a variable-length tail. If the tail computation goes negative,
        ``struct.unpack`` must raise rather than return garbage.
        """
        pkt = {eap.USER_PASSWORD_ATTR: [b"pw"]}
        reply = {eap.EAP_MESSAGE_ATTR: [b"\x01\x07"]}  # 2 bytes — header truncated

        with pytest.raises(struct.error):
            eap.apply_eap_md5_challenge(pkt, reply)
