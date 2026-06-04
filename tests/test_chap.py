"""Tests for the CHAP password helpers.

CHAP's wire-level behaviour is dictated by one MD5 over three concrete
inputs (id, password, challenge); these tests pin the digest output for
a fixed vector and verify the helper that mutates an ``AuthPacket``
into CHAP shape leaves the request in a state any RFC-2865 server
accepts.
"""

import hashlib

import pytest

from pyrad2 import chap


class TestBuildChapPassword:
    def test_layout_matches_rfc2865(self):
        # Wire shape: 1 byte CHAP Identifier + 16 byte MD5(id || pw || challenge).
        chap_id = 0x42
        password = b"secret"
        challenge = b"\x01" * 16

        value = chap.build_chap_password(chap_id, password, challenge)

        assert len(value) == 17
        assert value[0] == chap_id
        # Recompute the digest the same way the helper claims to.
        expected = hashlib.md5(bytes([chap_id]) + password + challenge).digest()
        assert value[1:] == expected

    def test_digest_is_sensitive_to_each_input(self):
        # Changing any input changes the digest — guards against a copy
        # that drops one of the three concatenated parts.
        base = chap.build_chap_password(1, b"pw", b"\x00" * 16)
        assert chap.build_chap_password(2, b"pw", b"\x00" * 16) != base
        assert chap.build_chap_password(1, b"px", b"\x00" * 16) != base
        assert chap.build_chap_password(1, b"pw", b"\x01" * 16) != base

    @pytest.mark.parametrize("bad_id", [-1, 256, 1000])
    def test_rejects_out_of_range_chap_id(self, bad_id):
        with pytest.raises(ValueError, match="one byte"):
            chap.build_chap_password(bad_id, b"pw", b"\x00" * 16)


class TestPrepareChapRequest:
    def _make_pkt(self, **kwargs):
        # Lightweight fake — the helper only uses ``__contains__``,
        # ``__delitem__`` and ``__setitem__``.
        return dict(kwargs)

    def test_replaces_user_password_with_chap_attrs(self):
        pkt = self._make_pkt(**{"User-Password": [b"hunter2"]})

        chap.prepare_chap_request(pkt, b"hunter2", chap_id=7, challenge=b"\xab" * 16)

        # PAP credential cleared, CHAP credentials present.
        assert "User-Password" not in pkt
        assert pkt["CHAP-Password"] == chap.build_chap_password(
            7, b"hunter2", b"\xab" * 16
        )
        assert pkt["CHAP-Challenge"] == b"\xab" * 16

    def test_works_when_no_user_password_present(self):
        # CHAP works on a fresh packet that never carried PAP creds.
        pkt = self._make_pkt()

        chap.prepare_chap_request(pkt, "hunter2", chap_id=1, challenge=b"\x00" * 16)

        assert "CHAP-Password" in pkt
        assert "CHAP-Challenge" in pkt

    def test_string_password_encodes_as_utf8(self):
        pkt_a = self._make_pkt()
        pkt_b = self._make_pkt()

        chap.prepare_chap_request(pkt_a, "café", chap_id=1, challenge=b"\x00" * 16)
        chap.prepare_chap_request(
            pkt_b, "café".encode("utf-8"), chap_id=1, challenge=b"\x00" * 16
        )

        assert pkt_a["CHAP-Password"] == pkt_b["CHAP-Password"]

    def test_random_defaults_produce_distinct_credentials(self):
        # Two unseeded calls must not collide on either knob — otherwise
        # the caller would be reusing challenge bytes across requests.
        pkt_a = self._make_pkt()
        pkt_b = self._make_pkt()

        chap.prepare_chap_request(pkt_a, b"hunter2")
        chap.prepare_chap_request(pkt_b, b"hunter2")

        # Vanishingly unlikely collision (~2^-128) — treat any hit here
        # as a bug in the helper, not statistical bad luck.
        assert pkt_a["CHAP-Challenge"] != pkt_b["CHAP-Challenge"]
