"""Tests for the EAP-GTC method.

Same shape as the EAP-MD5 tests: pin the byte layout of the response
payload, confirm the method satisfies the ``EapMethod`` contract, and
verify the registry binding so the clients pick the right method when
``auth_type="eap-gtc"``.
"""

import struct

import pytest

from pyrad2 import eap
from pyrad2.constants import EAPPacketType
from pyrad2.eap.gtc import (
    EAP_TYPE_GTC,
    GtcMethod,
    apply_eap_gtc_challenge,
    build_eap_gtc_response,
)


class TestBuildEapGtcResponse:
    def test_payload_layout_matches_rfc3748(self):
        password = b"hunter2"
        payload = build_eap_gtc_response(eap_id=7, password=password)

        code, eap_id, length, eap_type = struct.unpack("!BBHB", payload[:5])
        assert code == EAPPacketType.RESPONSE
        assert eap_id == 7
        assert eap_type == EAP_TYPE_GTC
        # Length field counts the EAP payload itself (5 header + data).
        assert length == 5 + len(password)
        assert payload[5:] == password

    def test_accepts_empty_password(self):
        # Edge case: zero-length data is well-formed per RFC 3748.
        payload = build_eap_gtc_response(eap_id=1, password=b"")
        assert len(payload) == 5

    def test_truncates_no_input(self):
        # Long passwords are passed through verbatim — the helper trusts
        # the AVP layer to fragment if necessary (concat / long-extended).
        long_pw = b"x" * 200
        payload = build_eap_gtc_response(eap_id=1, password=long_pw)
        assert payload[5:] == long_pw


class TestApplyEapGtcChallenge:
    def _make_challenge(self, eap_id=7, prompt=b"Password: ", state=b"opaque"):
        # Inbound EAP-Request/GTC header layout, then the prompt text.
        header = struct.pack("!BBHB", 1, eap_id, 5 + len(prompt), EAP_TYPE_GTC)
        return {eap.EAP_MESSAGE_ATTR: [header + prompt], eap.STATE_ATTR: [state]}

    def test_echoes_eap_id_and_copies_state(self):
        pkt = {eap.USER_PASSWORD_ATTR: [b"hunter2"]}

        apply_eap_gtc_challenge(pkt, self._make_challenge(eap_id=42))

        response = pkt[eap.EAP_MESSAGE_ATTR][0]
        # ID byte echoed verbatim.
        assert response[1] == 42
        # Password placed unchanged after the 5-byte header.
        assert response[5:] == b"hunter2"
        # Server's State must round-trip — multi-challenge sessions
        # rely on it for continuity.
        assert pkt[eap.STATE_ATTR] == [b"opaque"]

    def test_truncated_challenge_raises(self):
        # A 4-byte payload can't carry a full EAP header — the helper
        # must refuse it explicitly rather than indexing past the end.
        pkt = {eap.USER_PASSWORD_ATTR: [b"pw"]}
        bogus = {
            eap.EAP_MESSAGE_ATTR: [b"\x01\x07\x00"],  # 3 bytes only
            eap.STATE_ATTR: [b"s"],
        }

        with pytest.raises(ValueError, match="truncated"):
            apply_eap_gtc_challenge(pkt, bogus)


class TestGtcMethod:
    def test_registered_under_canonical_name(self):
        # The client lookup key is the string callers set as auth_type.
        assert isinstance(eap.get_method("eap-gtc"), GtcMethod)

    def test_start_delegates_to_shared_identity_helper(self):
        # GtcMethod.start should match the byte output of the legacy
        # inject_eap_identity helper so the EAP framing on the wire
        # stays consistent across registered methods.
        pkt_class = {eap.USER_PASSWORD_ATTR: [b"hunter2"]}
        pkt_free: dict = {eap.USER_PASSWORD_ATTR: [b"hunter2"]}

        GtcMethod().start(pkt_class)
        eap.inject_eap_identity(pkt_free)

        assert pkt_class[eap.EAP_MESSAGE_ATTR] == pkt_free[eap.EAP_MESSAGE_ATTR]

    def test_respond_matches_apply_eap_gtc_challenge(self):
        def _challenge():
            header = struct.pack("!BBHB", 1, 9, 5 + 4, EAP_TYPE_GTC)
            return {
                eap.EAP_MESSAGE_ATTR: [header + b"PIN:"],
                eap.STATE_ATTR: [b"st"],
            }

        pkt_class = {eap.USER_PASSWORD_ATTR: [b"1234"]}
        pkt_free: dict = {eap.USER_PASSWORD_ATTR: [b"1234"]}

        GtcMethod().respond(pkt_class, _challenge())
        apply_eap_gtc_challenge(pkt_free, _challenge())

        assert pkt_class[eap.EAP_MESSAGE_ATTR] == pkt_free[eap.EAP_MESSAGE_ATTR]
        assert pkt_class[eap.STATE_ATTR] == pkt_free[eap.STATE_ATTR]
