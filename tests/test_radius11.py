"""Unit + integration tests for RFC 9765 RADIUS/1.1 over RadSec."""

import asyncio
import io
import os
import socket
import ssl
import struct

import pytest

from pyrad2 import packet
from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.packet import AuthPacket, parse_packet
from pyrad2.radsec.client import RadSecClient
from pyrad2.radsec.server import RadSecServer
from pyrad2.radsec.v11 import (
    ALPN_V1_0,
    ALPN_V1_1,
    NoCommonRadiusVersion,
    RadiusVersion,
    TokenCounter,
    apply_alpn,
    enforce_tls_version_floor,
    negotiate,
    version_from_alpn,
)
from pyrad2.server import RemoteHost

from .base import TEST_ROOT_PATH

SERVER_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/server/server.cert.pem")
SERVER_KEYFILE = os.path.join(TEST_ROOT_PATH, "certs/server/server.key.pem")
CA_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/ca/ca.cert.pem")
CLIENT_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/client/client.cert.pem")
CLIENT_KEYFILE = os.path.join(TEST_ROOT_PATH, "certs/client/client.key.pem")

# The tests/certs/ certificates lack a SubjectAltName, so they can't satisfy
# hostname verification against 127.0.0.1 during a real TLS handshake. The
# repo's example certs do have the right SANs; use them for the integration
# tests below while keeping the unit-only tests on the tests/certs/ tree.
_EXAMPLE_ROOT = os.path.join(os.path.dirname(TEST_ROOT_PATH), "examples")
EXAMPLE_SERVER_CERTFILE = os.path.join(_EXAMPLE_ROOT, "certs/server/server.cert.pem")
EXAMPLE_SERVER_KEYFILE = os.path.join(_EXAMPLE_ROOT, "certs/server/server.key.pem")
EXAMPLE_CA_CERTFILE = os.path.join(_EXAMPLE_ROOT, "certs/ca/ca.cert.pem")
EXAMPLE_CLIENT_CERTFILE = os.path.join(_EXAMPLE_ROOT, "certs/client/client.cert.pem")
EXAMPLE_CLIENT_KEYFILE = os.path.join(_EXAMPLE_ROOT, "certs/client/client.key.pem")


class TestVersionFromAlpn:
    def test_none_defaults_to_v1_0(self):
        assert version_from_alpn(None) is RadiusVersion.V1_0

    def test_radius_1_0(self):
        assert version_from_alpn(ALPN_V1_0) is RadiusVersion.V1_0

    def test_radius_1_1(self):
        assert version_from_alpn(ALPN_V1_1) is RadiusVersion.V1_1

    def test_unknown_alpn_falls_back_to_v1_0(self):
        assert version_from_alpn("h2") is RadiusVersion.V1_0


class TestNegotiate:
    def test_peer_picked_supported_version(self):
        assert (
            negotiate((RadiusVersion.V1_0, RadiusVersion.V1_1), ALPN_V1_1)
            is RadiusVersion.V1_1
        )
        assert (
            negotiate((RadiusVersion.V1_0, RadiusVersion.V1_1), ALPN_V1_0)
            is RadiusVersion.V1_0
        )

    def test_peer_no_alpn_with_v1_0_in_config_falls_back(self):
        assert negotiate((RadiusVersion.V1_0,), None) is RadiusVersion.V1_0
        assert (
            negotiate((RadiusVersion.V1_0, RadiusVersion.V1_1), None)
            is RadiusVersion.V1_0
        )

    def test_peer_no_alpn_strict_v1_1_raises(self):
        """RFC 9765 §3.3: strict v1.1 must close, not downgrade."""
        with pytest.raises(NoCommonRadiusVersion):
            negotiate((RadiusVersion.V1_1,), None)

    def test_peer_picked_unsupported_version_raises(self):
        with pytest.raises(NoCommonRadiusVersion):
            negotiate((RadiusVersion.V1_0,), ALPN_V1_1)


class TestEnforceTlsVersionFloor:
    def test_v1_0_only_does_not_change_minimum(self):
        assert (
            enforce_tls_version_floor(ssl.TLSVersion.TLSv1_2, (RadiusVersion.V1_0,))
            is ssl.TLSVersion.TLSv1_2
        )

    def test_v1_1_promotes_to_1_3(self):
        assert (
            enforce_tls_version_floor(
                ssl.TLSVersion.TLSv1_2,
                (RadiusVersion.V1_0, RadiusVersion.V1_1),
            )
            is ssl.TLSVersion.TLSv1_3
        )

    def test_v1_1_keeps_caller_floor_if_already_high(self):
        assert (
            enforce_tls_version_floor(ssl.TLSVersion.TLSv1_3, (RadiusVersion.V1_1,))
            is ssl.TLSVersion.TLSv1_3
        )


class TestApplyAlpn:
    def setup_method(self):
        self.ctx = ssl.create_default_context()

    def test_v1_0_only_does_not_advertise_alpn(self):
        apply_alpn(self.ctx, (RadiusVersion.V1_0,))
        # Python doesn't expose set ALPN values; the contract is "leave the
        # context untouched" so existing tests assert behavior via the lack
        # of selected_alpn_protocol when no peer ALPN is offered. Calling
        # again must be idempotent and not raise.
        apply_alpn(self.ctx, (RadiusVersion.V1_0,))

    def test_v1_1_added_calls_set_alpn_with_v1_1_first(self):
        """Order matters: server-side ALPN picks the first match in the
        server's list, so v1.1 must lead for it to win when both sides
        advertise both versions."""
        recorded: list[list[str]] = []

        class _Ctx:
            def set_alpn_protocols(self, names):
                recorded.append(list(names))

        apply_alpn(_Ctx(), (RadiusVersion.V1_0, RadiusVersion.V1_1))
        assert recorded == [[ALPN_V1_1, ALPN_V1_0]]

    def test_empty_versions_raises(self):
        with pytest.raises(ValueError):
            apply_alpn(self.ctx, ())


class TestTokenCounter:
    def test_next_advances_by_one(self):
        tc = TokenCounter()
        first = int.from_bytes(tc.next(), "big")
        second = int.from_bytes(tc.next(), "big")
        assert second == (first + 1) & 0xFFFFFFFF

    def test_wraps_around_32_bits(self):
        tc = TokenCounter()
        tc._value = 0xFFFFFFFE
        assert int.from_bytes(tc.next(), "big") == 0xFFFFFFFE
        assert int.from_bytes(tc.next(), "big") == 0xFFFFFFFF
        assert int.from_bytes(tc.next(), "big") == 0


class TestPacketGating:
    """Direct tests that the radius_version flag swaps MD5 paths off."""

    @pytest.fixture(autouse=True)
    def _inject_dictionary(self, full_dictionary):
        self.dictionary = full_dictionary

    def _v11_auth_packet(self, **extra):
        token = TokenCounter().next()
        kwargs = dict(
            id=0,
            secret=b"radsec",
            dict=self.dictionary,
            radius_version=RadiusVersion.V1_1,
        )
        kwargs.update(extra)
        pkt = AuthPacket(**kwargs)
        pkt.token = token
        return pkt

    def test_pw_crypt_is_identity_in_v1_1(self):
        pkt = self._v11_auth_packet()
        assert pkt.pw_crypt("hunter2") == b"hunter2"

    def test_pw_decrypt_is_identity_in_v1_1(self):
        pkt = self._v11_auth_packet()
        assert pkt.pw_decrypt(b"hunter2") == "hunter2"

    def test_salt_crypt_is_identity_in_v1_1(self):
        pkt = self._v11_auth_packet()
        pkt["Test-Encrypted-String"] = "secret-value"
        # _encode_value bypasses salt_crypt → the raw bytes contain "secret-value".
        encoded = pkt._pkt_encode_attributes()
        assert b"secret-value" in encoded

    def test_add_message_authenticator_is_noop_in_v1_1(self):
        pkt = self._v11_auth_packet()
        pkt.add_message_authenticator()
        assert not pkt.has_message_authenticator()

    def test_ensure_message_authenticator_is_noop_in_v1_1(self):
        pkt = self._v11_auth_packet()
        pkt.ensure_message_authenticator()
        assert not pkt.has_message_authenticator()

    def test_validate_ma_policy_skips_in_v1_1(self):
        pkt = self._v11_auth_packet()
        pkt[79] = [b"\x02\x01\x00\x05\x01"]  # EAP-Message, no MA
        # In v1.0 this would raise; in v1.1 it must not.
        pkt.validate_message_authenticator_policy(
            require_message_authenticator=True,
            require_eap_message_authenticator=True,
        )

    def test_verify_auth_request_returns_true_in_v1_1(self):
        pkt = self._v11_auth_packet()
        raw = pkt.request_packet()
        parsed = parse_packet(
            raw, b"radsec", self.dictionary, radius_version=RadiusVersion.V1_1
        )
        assert parsed.verify_auth_request()

    def test_request_packet_emits_token_and_zero_id(self):
        pkt = self._v11_auth_packet(id=42)
        raw = pkt.request_packet()
        code, ident, length = struct.unpack("!BBH", raw[0:4])
        assert code == PacketType.AccessRequest
        # RFC 9765: Reserved-1 (formerly Identifier) MUST be zero.
        assert ident == 0
        assert length == len(raw)
        # The 12 bytes after the Token are Reserved-2 — MUST be zero.
        assert raw[8:20] == b"\x00" * 12
        # First 4 bytes after the header are the Token.
        assert raw[4:8] == pkt.token

    def test_reply_packet_echoes_request_token_and_skips_md5(self):
        request = self._v11_auth_packet()
        reply = request.create_reply()
        reply.code = PacketType.AccessAccept
        raw = reply.reply_packet()
        # Token round-trips into the reply.
        assert raw[4:8] == request.token
        # Reserved-1 byte (id slot) is zero on the wire.
        assert raw[1] == 0
        # No MD5 over (header || req_auth || attrs || secret) — Reserved-2 zero.
        assert raw[8:20] == b"\x00" * 12

    def test_verify_reply_matches_on_token_in_v1_1(self):
        request = self._v11_auth_packet()
        reply = request.create_reply()
        reply.code = PacketType.AccessAccept
        raw_reply = reply.reply_packet()
        parsed_reply = parse_packet(
            raw_reply, b"radsec", self.dictionary, radius_version=RadiusVersion.V1_1
        )
        assert request.verify_reply(parsed_reply, raw_reply)

    def test_verify_reply_rejects_wrong_token_in_v1_1(self):
        request = self._v11_auth_packet()
        reply = request.create_reply()
        reply.code = PacketType.AccessAccept
        raw_reply = bytearray(reply.reply_packet())
        # Flip a bit in the Token region.
        raw_reply[4] ^= 0xFF
        parsed_reply = parse_packet(
            bytes(raw_reply),
            b"radsec",
            self.dictionary,
            radius_version=RadiusVersion.V1_1,
        )
        assert not request.verify_reply(parsed_reply, bytes(raw_reply))

    def test_decode_silently_discards_message_authenticator_in_v1_1(self):
        """RFC 9765 §5.2: Message-Authenticator in a v1.1 packet must be
        silently discarded or treated as an invalid attribute. We do
        the former — handlers must not see it."""
        # Build a v1.0 packet that has a Message-Authenticator, then
        # re-parse it claiming v1.1. The attribute must vanish.
        v10 = AuthPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=self.dictionary,
        )
        v10.add_message_authenticator()
        raw = v10.request_packet()
        parsed = parse_packet(
            raw, b"radsec", self.dictionary, radius_version=RadiusVersion.V1_1
        )
        assert 80 not in parsed
        assert not parsed.has_message_authenticator()

    def test_set_obfuscated_user_password_v1_1_emits_plaintext(self, radsec_dictionary):
        # Use the integration test dictionary which carries User-Password.
        radsec_dict = radsec_dictionary
        token = TokenCounter().next()
        pkt = AuthPacket(
            id=0,
            secret=b"radsec",
            dict=radsec_dict,
            radius_version=RadiusVersion.V1_1,
        )
        pkt.token = token
        pkt.set_obfuscated("User-Password", "hunter2")
        raw = pkt.request_packet()
        parsed = parse_packet(
            raw, b"radsec", radsec_dict, radius_version=RadiusVersion.V1_1
        )
        assert parsed["User-Password"] == ["hunter2"]

    def test_set_obfuscated_user_password_v1_0_applies_pw_crypt(
        self, radsec_dictionary
    ):
        radsec_dict = radsec_dictionary
        pkt = AuthPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=radsec_dict,
        )
        pkt.set_obfuscated("User-Password", "hunter2")
        raw = pkt.request_packet()
        parsed = parse_packet(raw, b"radsec", radsec_dict)
        # Raw-key access returns the obfuscated bytes (skips the str
        # decoder applied by name-keyed lookups).
        obfuscated = parsed[2][0]
        assert isinstance(obfuscated, bytes)
        assert parsed.pw_decrypt(obfuscated) == "hunter2"
        # Plaintext must NOT be on the wire.
        assert b"hunter2" not in raw

    def test_set_obfuscated_encrypt_2_v1_1_emits_plaintext(self):
        """Tunnel-Password / MS-MPPE-style (encrypt=2) attributes also flow
        through the deferred path so a dual-advertise client doesn't lock
        itself into salt-encrypted bytes before the version is known."""
        pkt = self._v11_auth_packet()
        pkt.set_obfuscated("Test-Encrypted-String", "secret-value")
        raw = pkt.request_packet()
        parsed = parse_packet(
            raw, b"radsec", self.dictionary, radius_version=RadiusVersion.V1_1
        )
        assert parsed["Test-Encrypted-String"] == ["secret-value"]

    def test_set_obfuscated_encrypt_2_v1_0_applies_salt_crypt(self):
        """Same deferred call lands on the v1.0 salt_crypt path when
        radius_version stays at V1_0."""
        pkt = AuthPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=self.dictionary,
        )
        pkt.set_obfuscated("Test-Encrypted-String", "secret-value")
        raw = pkt.request_packet()
        parsed = parse_packet(raw, b"radsec", self.dictionary)
        assert parsed["Test-Encrypted-String"] == ["secret-value"]

    def test_serialization_does_not_mutate_packet_dict(self, radsec_dictionary):
        """Regression for P3: ``_pkt_encode_attributes`` used to delete
        and re-add deferred attribute codes on every serialization,
        leaving the packet in different shape after the call. The pure
        path must leave ``self`` untouched."""
        radsec_dict = radsec_dictionary
        pkt = AuthPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=radsec_dict,
        )
        pkt.set_obfuscated("User-Password", "hunter2")
        # Snapshot stored state BEFORE serialization.
        before_keys = list(pkt.keys())
        before_deferred = {k: list(v) for k, v in pkt._deferred_obfuscated.items()}

        _ = pkt.request_packet()
        # Stored attribute keys unchanged; deferred sidecar unchanged.
        assert list(pkt.keys()) == before_keys
        assert {
            k: list(v) for k, v in pkt._deferred_obfuscated.items()
        } == before_deferred

        # And a second serialization is byte-stable.
        first = pkt.request_packet()
        second = pkt.request_packet()
        assert first == second

    def test_v1_1_request_packet_does_not_seed_legacy_authenticator(self):
        """P3 readability fix: a v1.1 Access-Request must not run the
        v1.0 ``create_authenticator`` path even though it doesn't leak
        onto the wire — it leaves misleading state on the packet."""
        token = TokenCounter().next()
        pkt = AuthPacket(
            id=0,
            secret=b"radsec",
            dict=self.dictionary,
            radius_version=RadiusVersion.V1_1,
        )
        pkt.token = token
        assert pkt.authenticator is None
        _ = pkt.request_packet()
        # Serializer must not have populated self.authenticator on the
        # v1.1 path.
        assert pkt.authenticator is None

    def test_set_obfuscated_re_encodes_when_version_flips(self, radsec_dictionary):
        """RFC 9765 §3.5: a TLS resumption might land on a different ALPN
        than the original session. The plaintext sidecar must remain
        authoritative so a re-serialization picks up the new version
        rather than replaying the v1.0 ciphertext under v1.1 semantics
        (or vice versa)."""
        radsec_dict = radsec_dictionary
        pkt = AuthPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=radsec_dict,
        )
        pkt.set_obfuscated("User-Password", "hunter2")

        # First serialize under v1.0 — wire bytes are obfuscated.
        raw_v10 = pkt.request_packet()
        assert b"hunter2" not in raw_v10
        # decrypt to confirm round-trip works
        parsed_v10 = parse_packet(raw_v10, b"radsec", radsec_dict)
        assert parsed_v10.pw_decrypt(parsed_v10[2][0]) == "hunter2"

        # Flip the packet to v1.1 (simulating a reconnect that negotiated
        # the modern profile) and serialize again. The wire bytes MUST
        # now be plaintext, not the stale v1.0 obfuscation.
        pkt.radius_version = RadiusVersion.V1_1
        pkt.token = TokenCounter().next()
        raw_v11 = pkt.request_packet()
        assert b"hunter2" in raw_v11
        parsed_v11 = parse_packet(
            raw_v11, b"radsec", radsec_dict, radius_version=RadiusVersion.V1_1
        )
        assert parsed_v11["User-Password"] == ["hunter2"]

        # And back to v1.0 — must re-obfuscate freshly, not reuse the
        # v1.1 plaintext from the second pass.
        pkt.radius_version = RadiusVersion.V1_0
        raw_v10_again = pkt.request_packet()
        assert b"hunter2" not in raw_v10_again

    def test_pack_v11_header_requires_token(self):
        from pyrad2.packet import _pack_v11_header
        from pyrad2.exceptions import PacketError as PErr

        with pytest.raises(PErr):
            _pack_v11_header(1, 20, None)

    def test_pack_v11_header_rejects_wrong_size_token(self):
        from pyrad2.packet import _pack_v11_header
        from pyrad2.exceptions import PacketError as PErr

        with pytest.raises(PErr):
            _pack_v11_header(1, 20, b"too-long-token")

    def test_pack_v11_header_zero_token_escape_hatch(self):
        from pyrad2.packet import _pack_v11_header

        raw = _pack_v11_header(1, 20, None, zero_token=True)
        assert raw[4:8] == b"\x00\x00\x00\x00"
        assert raw[8:20] == b"\x00" * 12

    def test_request_packet_without_token_raises_clearly(self):
        """A v1.1 packet missing its Token should fail loudly at serialize
        time rather than silently emit a zero Token that looks like a
        Protocol-Error reply."""
        from pyrad2.exceptions import PacketError as PErr

        pkt = AuthPacket(
            id=0,
            secret=b"radsec",
            dict=self.dictionary,
            radius_version=RadiusVersion.V1_1,
        )
        # No pkt.token = ...
        with pytest.raises(PErr):
            pkt.request_packet()

    def test_v11_packet_after_pw_crypt_has_zero_reserved_2(self):
        """Even when v1.0-style pw_crypt() has seeded packet.authenticator
        with random 16 bytes, the v1.1 wire emission MUST leave Reserved-2
        zeroed (RFC 9765 §4.1). Regression for the Token/authenticator
        separation."""
        pkt = self._v11_auth_packet()
        # Pretend a v1.0-style caller ran pw_crypt first — this populates
        # self.authenticator with 16 random bytes.
        _ = AuthPacket(
            id=0,
            secret=b"radsec",
            dict=self.dictionary,
        ).pw_crypt("hunter2")  # warm-up, not used; ensures helper still works
        # Now stuff random bytes into authenticator on the v1.1 packet and
        # confirm they don't leak.
        import os as _os

        pkt.authenticator = _os.urandom(16)
        raw = pkt.request_packet()
        assert raw[4:8] == pkt.token
        assert raw[8:20] == b"\x00" * 12

    def test_v1_0_packet_is_unchanged_after_radius_version_added(self):
        """Sanity: default radius_version=V1_0 still produces a v1.0-shaped packet."""
        pkt = AuthPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=self.dictionary,
        )
        raw = pkt.request_packet()
        # Identifier preserved (not zeroed). Authenticator preserved.
        assert raw[1] == 1
        assert raw[4:20] == b"0123456789ABCDEF"

    def test_create_reply_propagates_radius_version(self):
        request = self._v11_auth_packet()
        reply = request.create_reply()
        assert reply.radius_version == RadiusVersion.V1_1

    def test_parse_packet_v1_1_round_trip(self):
        """Test that a v1.1 packet can be encoded, then parsed back with attributes intact."""
        sent = self._v11_auth_packet()
        sent["Test-Encrypted-String"] = "rfc9765"  # encrypt=2 attribute
        raw = sent.request_packet()
        parsed = parse_packet(
            raw, b"radsec", self.dictionary, radius_version=RadiusVersion.V1_1
        )
        # No MD5 obfuscation, no salt framing — raw value flows through.
        assert parsed["Test-Encrypted-String"] == ["rfc9765"]


_VENDOR_DICT_TEXT = """
VENDOR Microsoft 311
BEGIN-VENDOR Microsoft
ATTRIBUTE MS-MPPE-Recv-Key 17 octets encrypt=2
END-VENDOR Microsoft
"""


def _vendor_dictionary() -> Dictionary:
    """Tiny test dictionary carrying a vendor encrypt=2 attribute."""
    return Dictionary(io.StringIO(_VENDOR_DICT_TEXT))


class TestDeferredObfuscatedVendor:
    """Regression: set_obfuscated() must wrap vendor attributes in
    Vendor-Specific (code 26) rather than emit a raw top-level AVP with
    the vendor-internal code. Otherwise MS-MPPE-Recv-Key (Microsoft
    sub-type 17, encrypt=2) would emit as RADIUS attribute 17, which is
    Reply-Message in the standard registry."""

    def setup_method(self):
        self.dictionary = _vendor_dictionary()

    def test_set_obfuscated_vendor_attribute_v1_1_emits_vsa(self):
        pkt = AuthPacket(
            id=0,
            secret=b"radsec",
            dict=self.dictionary,
            radius_version=RadiusVersion.V1_1,
        )
        pkt.token = TokenCounter().next()
        pkt.set_obfuscated("MS-MPPE-Recv-Key", b"secret")
        raw = pkt.request_packet()

        # First attribute after the 20-byte header MUST be VSA (code 26),
        # not the bare vendor-internal sub-type 17 (Reply-Message).
        assert raw[20] == 26, "deferred vendor attr must wrap in VSA-26"
        vendor_id = struct.unpack("!L", raw[22:26])[0]
        assert vendor_id == 311

        # Round-trip: parsing back yields the vendor attribute with the
        # plaintext (v1.1 skips salt obfuscation).
        parsed = parse_packet(
            raw, b"radsec", self.dictionary, radius_version=RadiusVersion.V1_1
        )
        assert parsed["MS-MPPE-Recv-Key"] == [b"secret"]

    def test_set_obfuscated_vendor_attribute_v1_0_emits_vsa_with_salt(self):
        pkt = AuthPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=self.dictionary,
        )
        pkt.set_obfuscated("MS-MPPE-Recv-Key", b"secret")
        raw = pkt.request_packet()

        assert raw[20] == 26
        vendor_id = struct.unpack("!L", raw[22:26])[0]
        assert vendor_id == 311
        # Plaintext must NOT be on the wire — salt_crypt was applied.
        assert b"secret" not in raw

        # Re-parse and ensure decrypt round-trips back to the plaintext.
        parsed = parse_packet(raw, b"radsec", self.dictionary)
        assert parsed["MS-MPPE-Recv-Key"] == [b"secret"]


_TLV_DICT_TEXT = """
ATTRIBUTE TestTlv 60 tlv
ATTRIBUTE TestTlv-Secret 60.1 string encrypt=2
ATTRIBUTE TestTlv-Label 60.2 string
"""


_EVS_DICT_TEXT = """
ATTRIBUTE Extended-Attribute-1 241 extended
ATTRIBUTE Extended-Vendor-Specific-1 241.26 evs
VENDOR Example 12345
BEGIN-VENDOR Example parent=Extended-Vendor-Specific-1
ATTRIBUTE Example-Secret 1 octets encrypt=2
END-VENDOR Example
"""


class TestDeferredObfuscatedContainer:
    """Generalizes the VSA regression: deferred obfuscation must preserve
    whatever container framing the dictionary defines (TLV nesting, EVS
    4-tuple keys, extended-attribute parents), not just the plain
    top-level VSA case."""

    def test_deferred_tlv_subattribute_wraps_in_tlv_parent(self):
        """A deferred encrypt=2 TLV sub-attribute must be emitted nested
        under its TLV parent code, not as a top-level AVP with the bare
        sub-attribute code."""
        dictionary = Dictionary(io.StringIO(_TLV_DICT_TEXT))
        pkt = AuthPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=dictionary,
        )
        pkt.set_obfuscated("TestTlv-Secret", "value")
        raw = pkt.request_packet()

        # First AVP after the 20-byte header must be the TLV parent (60),
        # not the sub-attribute code (1).
        assert raw[20] == 60, "deferred TLV sub must nest under parent"
        # Re-parse and confirm the value round-trips through the TLV path.
        parsed = parse_packet(raw, b"radsec", dictionary)
        # Containerized read: TestTlv is a dict keyed by sub-name.
        container = parsed["TestTlv"]
        assert "TestTlv-Secret" in container
        assert container["TestTlv-Secret"] == ["value"]

    def test_deferred_tlv_subattribute_v1_1_emits_plaintext_in_tlv(self):
        """Same TLV nesting in v1.1, but the inner bytes are plaintext."""
        dictionary = Dictionary(io.StringIO(_TLV_DICT_TEXT))
        pkt = AuthPacket(
            id=0,
            secret=b"radsec",
            dict=dictionary,
            radius_version=RadiusVersion.V1_1,
        )
        pkt.token = TokenCounter().next()
        pkt.set_obfuscated("TestTlv-Secret", "value")
        raw = pkt.request_packet()

        assert raw[20] == 60
        # Plaintext value rides in the wire inside the TLV envelope.
        assert b"value" in raw
        parsed = parse_packet(
            raw, b"radsec", dictionary, radius_version=RadiusVersion.V1_1
        )
        assert parsed["TestTlv"]["TestTlv-Secret"] == ["value"]

    def test_deferred_tlv_subattribute_preserves_non_deferred_siblings(self):
        """Regression: a deferred TLV sub-attribute must not drop a
        directly-assigned sibling under the same TLV parent. The pre-fix
        behavior emitted only the deferred sub-code because the main
        encoder skipped the entire parent group."""
        dictionary = Dictionary(io.StringIO(_TLV_DICT_TEXT))
        pkt = AuthPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=dictionary,
        )
        # add_attribute is what TLV-nests under the parent; plain __setitem__
        # would store the sibling flat at top-level (separate quirk).
        pkt.add_attribute("TestTlv-Label", "visible")
        pkt.set_obfuscated("TestTlv-Secret", "value")
        raw = pkt.request_packet()

        parsed = parse_packet(raw, b"radsec", dictionary)
        container = parsed["TestTlv"]
        # Both sub-attributes ride on the wire under the same TLV parent.
        assert "TestTlv-Secret" in container
        assert "TestTlv-Label" in container
        assert container["TestTlv-Secret"] == ["value"]
        assert container["TestTlv-Label"] == ["visible"]

    def test_deferred_evs_attribute_emits_extended_vsa(self):
        """A deferred encrypt=2 EVS attribute must be encoded through the
        4-tuple EVS path, not crash on tuple-unpack in _pkt_encode_attribute."""
        dictionary = Dictionary(io.StringIO(_EVS_DICT_TEXT))
        pkt = AuthPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=dictionary,
        )
        pkt.set_obfuscated("Example-Secret", b"hush")

        # The reviewer's repro: would crash with
        # "too many values to unpack" before this fix.
        raw = pkt.request_packet()

        # First AVP after the 20-byte header is the extended parent (241).
        assert raw[20] == 241
        # Plaintext must NOT be on the wire (v1.0 salt obfuscation applied).
        assert b"hush" not in raw

        parsed = parse_packet(raw, b"radsec", dictionary)
        # Round-trips through the same EVS path.
        assert parsed["Example-Secret"] == [b"hush"]


class TestStampRadiusVersion:
    """Tests for RadSecClient._stamp_radius_version without a TLS handshake."""

    @pytest.fixture(autouse=True)
    def _setup(self, radsec_dictionary):
        self.dictionary = radsec_dictionary
        self.client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            dict=self.dictionary,
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
            radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1),
        )

    def _make_packet(self):
        return self.client.create_auth_packet(User_Name="alice")

    def test_v1_0_negotiation_clears_prior_v1_1_state(self):
        """Regression: a packet that was previously stamped V1_1 must
        not stay V1_1 after the connection falls back to v1.0 on
        reconnect. Otherwise the v1.1 serializer fires and we leak a
        Token/zero-id/plaintext-password onto the v1.0 wire."""
        pkt = self._make_packet()
        # Simulate a prior round where v1.1 was negotiated.
        from pyrad2.radsec.v11 import TokenCounter

        pkt.radius_version = RadiusVersion.V1_1
        pkt.token = TokenCounter().next()
        # Now negotiate v1.0 and re-stamp.
        self.client._negotiated_version = RadiusVersion.V1_0
        self.client._token_counter = None
        self.client._stamp_radius_version(pkt)
        assert pkt.radius_version is RadiusVersion.V1_0
        assert pkt.token is None

    def test_v1_1_negotiation_stamps_token(self):
        pkt = self._make_packet()
        self.client._negotiated_version = RadiusVersion.V1_1
        from pyrad2.radsec.v11 import TokenCounter

        self.client._token_counter = TokenCounter()
        self.client._stamp_radius_version(pkt)
        assert pkt.radius_version is RadiusVersion.V1_1
        assert pkt.token is not None
        assert len(pkt.token) == 4

    def test_v1_1_negotiation_preserves_existing_token(self):
        """The Token is allocated exactly once per packet; a retry must
        reuse it so the server's RFC 5080 dedup cache replays the same
        cached reply."""
        pkt = self._make_packet()
        original_token = b"\xde\xad\xbe\xef"
        pkt.token = original_token
        self.client._negotiated_version = RadiusVersion.V1_1
        from pyrad2.radsec.v11 import TokenCounter

        self.client._token_counter = TokenCounter()
        self.client._stamp_radius_version(pkt)
        assert pkt.token == original_token


class TestV11StatusServerVerifier:
    """RFC 9765 §5.2 forbids Message-Authenticator in v1.1 — the
    Status-Server verifier must NOT fall back to a Message-Authenticator
    check or it would reject valid v1.1 health packets."""

    @pytest.fixture(autouse=True)
    def _inject_dictionary(self, radsec_dictionary):
        self.dictionary = radsec_dictionary

    def test_v1_1_status_request_verifies_without_message_authenticator(self):
        token = TokenCounter().next()
        request = packet.StatusPacket(
            id=0,
            secret=b"radsec",
            dict=self.dictionary,
            radius_version=RadiusVersion.V1_1,
        )
        request.token = token
        raw = request.request_packet()
        parsed = parse_packet(
            raw, b"radsec", self.dictionary, radius_version=RadiusVersion.V1_1
        )
        # The packet's own verifier returns True (TLS authenticates).
        assert parsed.verify_status_request()

    def test_v1_0_status_request_still_requires_message_authenticator(self):
        # A v1.0 Status-Server without MA must fail verification.
        request = packet.StatusPacket(
            id=1,
            secret=b"radsec",
            authenticator=b"0123456789ABCDEF",
            dict=self.dictionary,
        )
        raw = request.request_packet()  # this would normally add MA
        # Strip the Message-Authenticator AVP by re-parsing without it.
        parsed = parse_packet(raw, b"radsec", self.dictionary)
        # The MA is present (auto-added on Status-Server). Force-remove.
        if 80 in parsed:
            del parsed[80]
        parsed.message_authenticator = None
        assert not parsed.verify_status_request()

    def test_radsec_server_v1_1_status_passes_verify_packet(self):
        from pyrad2.radsec.server import RadSecServer

        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            verify_packet=True,
        )
        token = TokenCounter().next()
        request = packet.StatusPacket(
            id=0,
            secret=b"radsec",
            dict=self.dictionary,
            radius_version=RadiusVersion.V1_1,
        )
        request.token = token
        raw = request.request_packet()
        parsed = parse_packet(
            raw, b"radsec", self.dictionary, radius_version=RadiusVersion.V1_1
        )
        assert server._verify_packet(parsed)


class TestV11Chap:
    """RFC 9765 §5.1.2: CHAP-Password requires explicit CHAP-Challenge."""

    @pytest.fixture(autouse=True)
    def _inject_dictionary(self, radsec_dictionary):
        self.dictionary = radsec_dictionary

    def test_v1_1_chap_without_challenge_raises(self):
        from pyrad2.exceptions import PacketError as PErr

        pkt = packet.AuthPacket(
            id=0,
            secret=b"radsec",
            dict=self.dictionary,
            radius_version=RadiusVersion.V1_1,
        )
        # Synthesize a 17-byte CHAP-Password (ident byte + 16-byte hash).
        pkt[3] = [b"\x01" + b"\x00" * 16]
        with pytest.raises(PErr):
            pkt.verify_chap_passwd("hunter2")


class TestRadSecAlpnConfiguration:
    """RadSecServer / RadSecClient apply ALPN to their SSL context as configured."""

    @pytest.fixture(autouse=True)
    def _inject_dictionary(self, radsec_dictionary):
        self.dictionary = radsec_dictionary

    def test_server_default_v1_0_only(self):
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
        )
        assert server.radius_versions == (RadiusVersion.V1_0,)

    def test_server_both_versions_advertises_alpn(self):
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1),
        )
        assert server.radius_versions == (RadiusVersion.V1_0, RadiusVersion.V1_1)

    def test_client_default_v1_0_only(self):
        client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            dict=self.dictionary,
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
        )
        assert client.radius_versions == (RadiusVersion.V1_0,)
        assert client._negotiated_version is RadiusVersion.V1_0
        assert client._token_counter is None

    def test_empty_versions_raises_on_server(self):
        with pytest.raises(ValueError):
            RadSecServer(
                certfile=SERVER_CERTFILE,
                keyfile=SERVER_KEYFILE,
                ca_certfile=CA_CERTFILE,
                dictionary=self.dictionary,
                radius_versions=(),
            )

    def test_empty_versions_raises_on_client(self):
        with pytest.raises(ValueError):
            RadSecClient(
                server="127.0.0.1",
                secret=b"radsec",
                dict=self.dictionary,
                certfile=CLIENT_CERTFILE,
                keyfile=CLIENT_KEYFILE,
                certfile_server=CA_CERTFILE,
                radius_versions=(),
            )


def _free_port() -> int:
    """Grab a free local TCP port for an integration test server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _IntegrationServer(RadSecServer):
    captured: AuthPacket | None = None

    # Tests below build legacy v1.0 packets without a Message-Authenticator
    # AVP. Default the BlastRADIUS knob off so the negotiation/round-trip
    # tests keep working.
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("require_message_authenticator", False)
        super().__init__(*args, **kwargs)

    async def handle_access_request(self, packet):
        type(self).captured = packet
        reply = packet.create_reply()
        reply.code = PacketType.AccessAccept
        reply["Reply-Message"] = "ok"
        return reply

    async def handle_accounting(self, packet):
        return packet.create_reply()


class TestRadSecV11EndToEnd:
    """Full TLS handshake → ALPN negotiation → v1.1 packet round-trip."""

    @pytest.fixture(autouse=True)
    def _setup(self, radsec_dictionary):
        self.dictionary = radsec_dictionary
        self.port = _free_port()
        _IntegrationServer.captured = None

    async def _start_server(self, *, radius_versions):
        server = _IntegrationServer(
            listen_address="127.0.0.1",
            listen_port=self.port,
            certfile=EXAMPLE_SERVER_CERTFILE,
            keyfile=EXAMPLE_SERVER_KEYFILE,
            ca_certfile=EXAMPLE_CA_CERTFILE,
            dictionary=self.dictionary,
            radius_versions=radius_versions,
        )
        server.hosts = {"127.0.0.1": RemoteHost("127.0.0.1", b"radsec", "test")}
        listener = await asyncio.start_server(
            server._handle_client,
            host=server.listen_address,
            port=server.listen_port,
            ssl=server.ssl_ctx,
        )
        return server, listener

    async def _stop_server(self, listener):
        listener.close()
        await listener.wait_closed()

    async def test_both_sides_advertise_both_versions_negotiates_v1_1(self):
        server, listener = await self._start_server(
            radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1)
        )
        try:
            client = RadSecClient(
                server="127.0.0.1",
                port=self.port,
                secret=b"radsec",
                dict=self.dictionary,
                certfile=EXAMPLE_CLIENT_CERTFILE,
                keyfile=EXAMPLE_CLIENT_KEYFILE,
                certfile_server=EXAMPLE_CA_CERTFILE,
                radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1),
            )
            try:
                request = client.create_auth_packet(User_Name="alice")
                # The version-agnostic API: set_obfuscated defers encoding
                # until send time, so the same call works whether v1.0 or
                # v1.1 ends up negotiated.
                request.set_obfuscated("User-Password", "hunter2")
                reply = await client.send_packet(request)
                assert reply is not None
                assert reply.code == PacketType.AccessAccept
                assert client._negotiated_version == RadiusVersion.V1_1
                assert client._token_counter is not None
                assert _IntegrationServer.captured is not None
                assert _IntegrationServer.captured.radius_version == RadiusVersion.V1_1
                # Password arrived in cleartext over TLS — no MD5 obfuscation.
                assert _IntegrationServer.captured["User-Password"] == ["hunter2"]
            finally:
                await client.close()
        finally:
            await self._stop_server(listener)

    async def test_asymmetric_v1_0_server_v1_1_client_negotiates_v1_0(self):
        """Server only knows v1.0; client offers both. Negotiation must land
        on v1.0 — both sides agree, no ALPN alert."""
        server, listener = await self._start_server(
            radius_versions=(RadiusVersion.V1_0,)
        )
        try:
            client = RadSecClient(
                server="127.0.0.1",
                port=self.port,
                secret=b"radsec",
                dict=self.dictionary,
                certfile=EXAMPLE_CLIENT_CERTFILE,
                keyfile=EXAMPLE_CLIENT_KEYFILE,
                certfile_server=EXAMPLE_CA_CERTFILE,
                radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1),
            )
            try:
                request = client.create_auth_packet(User_Name="alice")
                reply = await client.send_packet(request)
                assert reply is not None
                assert reply.code == PacketType.AccessAccept
                # Server didn't advertise ALPN at all; client falls back to v1.0.
                assert client._negotiated_version == RadiusVersion.V1_0
                assert client._token_counter is None
                assert _IntegrationServer.captured.radius_version == RadiusVersion.V1_0
            finally:
                await client.close()
        finally:
            await self._stop_server(listener)

    async def test_strict_v1_1_server_closes_when_client_offers_no_alpn(self):
        """RFC 9765 §3.3: a server configured for v1.1 only MUST close the
        connection when the client offered no ALPN. The previous behavior
        silently downgraded to v1.0 — flipped here to enforce the spec."""
        server, listener = await self._start_server(
            radius_versions=(RadiusVersion.V1_1,)
        )
        try:
            client = RadSecClient(
                server="127.0.0.1",
                port=self.port,
                secret=b"radsec",
                dict=self.dictionary,
                certfile=EXAMPLE_CLIENT_CERTFILE,
                keyfile=EXAMPLE_CLIENT_KEYFILE,
                certfile_server=EXAMPLE_CA_CERTFILE,
                radius_versions=(RadiusVersion.V1_0,),
                retries=1,
            )
            try:
                request = client.create_auth_packet(User_Name="alice")
                # The server hangs up immediately after the TLS handshake;
                # _send_packet swallows the resulting EOF and returns None.
                reply = await client.send_packet(request)
                assert reply is None
                # Handler must not have been invoked.
                assert _IntegrationServer.captured is None
            finally:
                await client.close()
        finally:
            await self._stop_server(listener)

    async def test_strict_v1_1_client_raises_when_server_offers_no_alpn(self):
        """RFC 9765 §3.3: a strict v1.1 client must not silently downgrade
        when the server didn't advertise the radius/1.1 ALPN at all."""
        server, listener = await self._start_server(
            radius_versions=(RadiusVersion.V1_0,)
        )
        try:
            client = RadSecClient(
                server="127.0.0.1",
                port=self.port,
                secret=b"radsec",
                dict=self.dictionary,
                certfile=EXAMPLE_CLIENT_CERTFILE,
                keyfile=EXAMPLE_CLIENT_KEYFILE,
                certfile_server=EXAMPLE_CA_CERTFILE,
                radius_versions=(RadiusVersion.V1_1,),
                retries=1,
            )
            try:
                request = client.create_auth_packet(User_Name="alice")
                reply = await client.send_packet(request)
                # _send_packet absorbs PacketError into a None return,
                # but client.last_error MUST surface the cause so callers
                # can tell a strict-mode refusal apart from a timeout.
                assert reply is None
                assert client.last_error is not None
                assert "No common RADIUS protocol" in str(client.last_error)
            finally:
                await client.close()
        finally:
            await self._stop_server(listener)

    async def test_last_error_cleared_on_successful_send(self):
        """A successful send should clear any prior negotiation failure
        so callers polling ``last_error`` don't see stale state."""
        server, listener = await self._start_server(
            radius_versions=(RadiusVersion.V1_0,)
        )
        try:
            client = RadSecClient(
                server="127.0.0.1",
                port=self.port,
                secret=b"radsec",
                dict=self.dictionary,
                certfile=EXAMPLE_CLIENT_CERTFILE,
                keyfile=EXAMPLE_CLIENT_KEYFILE,
                certfile_server=EXAMPLE_CA_CERTFILE,
                radius_versions=(RadiusVersion.V1_0,),
            )
            client.last_error = RuntimeError("from a prior call")
            try:
                reply = await client.send_packet(
                    client.create_auth_packet(User_Name="alice")
                )
                assert reply is not None
                assert client.last_error is None
            finally:
                await client.close()
        finally:
            await self._stop_server(listener)

    async def test_both_sides_v1_0_only_no_alpn_negotiated(self):
        server, listener = await self._start_server(
            radius_versions=(RadiusVersion.V1_0,)
        )
        try:
            client = RadSecClient(
                server="127.0.0.1",
                port=self.port,
                secret=b"radsec",
                dict=self.dictionary,
                certfile=EXAMPLE_CLIENT_CERTFILE,
                keyfile=EXAMPLE_CLIENT_KEYFILE,
                certfile_server=EXAMPLE_CA_CERTFILE,
                radius_versions=(RadiusVersion.V1_0,),
            )
            try:
                request = client.create_auth_packet(User_Name="alice")
                reply = await client.send_packet(request)
                assert reply is not None
                assert reply.code == PacketType.AccessAccept
                assert client._negotiated_version == RadiusVersion.V1_0
                assert client._token_counter is None
                assert _IntegrationServer.captured.radius_version == RadiusVersion.V1_0
            finally:
                await client.close()
        finally:
            await self._stop_server(listener)
