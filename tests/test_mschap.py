"""Tests for the MS-CHAPv2 helpers.

The end-to-end vector from RFC 2759 §D pins every primitive in the
chain — ``challenge_hash``, ``nt_password_hash``,
``challenge_response``, ``generate_nt_response``, and
``generate_authenticator_response`` — to known-good bytes for one
fully-worked example. Every other test layers on top of those to
verify wire packing, error paths, and the ``verify_*`` helpers.
"""

import pytest
from pyrad2 import mschap

cryptography = pytest.importorskip("cryptography")  # noqa: F841 — extras guard.

# RFC 2759 §D vector — User="User", Password="clientPass".
RFC_AUTH_CHALLENGE = bytes.fromhex("5B5D7C7D7B3F2F3E3C2C602132262628")
RFC_PEER_CHALLENGE = bytes.fromhex("21402324255E262A28295F2B3A337C7E")
RFC_USER = "User"
RFC_PASSWORD = "clientPass"
RFC_CHALLENGE_HASH = bytes.fromhex("D02E4386BCE91226")
RFC_NT_PASSWORD_HASH = bytes.fromhex("44EBBA8D5312B8D611474411F56989AE")
RFC_NT_RESPONSE = bytes.fromhex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
RFC_AUTHENTICATOR_RESPONSE = b"S=407A5589115FD0D6209F510FE9C04566932CDA56"


class TestRfcVector:
    """One full pass through the RFC 2759 §D test inputs."""

    def test_challenge_hash(self):
        assert (
            mschap.challenge_hash(RFC_PEER_CHALLENGE, RFC_AUTH_CHALLENGE, RFC_USER)
            == RFC_CHALLENGE_HASH
        )

    def test_nt_password_hash(self):
        assert mschap.nt_password_hash(RFC_PASSWORD) == RFC_NT_PASSWORD_HASH

    def test_generate_nt_response(self):
        assert (
            mschap.generate_nt_response(
                RFC_AUTH_CHALLENGE, RFC_PEER_CHALLENGE, RFC_USER, RFC_PASSWORD
            )
            == RFC_NT_RESPONSE
        )

    def test_generate_authenticator_response(self):
        assert (
            mschap.generate_authenticator_response(
                RFC_PASSWORD,
                RFC_NT_RESPONSE,
                RFC_PEER_CHALLENGE,
                RFC_AUTH_CHALLENGE,
                RFC_USER,
            )
            == RFC_AUTHENTICATOR_RESPONSE
        )


class TestChallengeHash:
    def test_accepts_bytes_username(self):
        # Strings and bytes for the user_name must give the same result.
        a = mschap.challenge_hash(RFC_PEER_CHALLENGE, RFC_AUTH_CHALLENGE, RFC_USER)
        b = mschap.challenge_hash(
            RFC_PEER_CHALLENGE, RFC_AUTH_CHALLENGE, RFC_USER.encode()
        )
        assert a == b

    def test_rejects_wrong_challenge_size(self):
        with pytest.raises(ValueError, match="Peer challenge"):
            mschap.challenge_hash(b"\x00" * 8, b"\x00" * 16, "u")
        with pytest.raises(ValueError, match="Authenticator challenge"):
            mschap.challenge_hash(b"\x00" * 16, b"\x00" * 8, "u")


class TestNtPasswordHash:
    def test_str_and_utf16le_bytes_match(self):
        a = mschap.nt_password_hash("Hello")
        b = mschap.nt_password_hash("Hello".encode("utf-16-le"))
        assert a == b

    def test_hash_nt_password_hash_rejects_wrong_size(self):
        with pytest.raises(ValueError, match="NT password hash"):
            mschap.hash_nt_password_hash(b"\x00" * 15)


class TestChallengeResponse:
    def test_rejects_wrong_sizes(self):
        with pytest.raises(ValueError, match="Challenge must be 8 bytes"):
            mschap.challenge_response(b"\x00" * 7, b"\x00" * 16)
        with pytest.raises(ValueError, match="Password hash must be 16 bytes"):
            mschap.challenge_response(b"\x00" * 8, b"\x00" * 17)

    def test_response_is_twenty_four_bytes(self):
        out = mschap.challenge_response(RFC_CHALLENGE_HASH, RFC_NT_PASSWORD_HASH)
        assert len(out) == 24


class TestBuildMschap2Response:
    def test_layout_and_size(self):
        peer = b"\xaa" * 16
        nt = b"\x55" * 24
        out = mschap.build_mschap2_response(
            ident=7, peer_challenge=peer, nt_response=nt, flags=0
        )

        assert len(out) == 50
        assert out[0] == 7
        assert out[1] == 0  # flags
        assert out[2:18] == peer
        assert out[18:26] == b"\x00" * 8  # reserved
        assert out[26:50] == nt

    @pytest.mark.parametrize("bad", [-1, 256, 999])
    def test_rejects_out_of_range_ident(self, bad):
        with pytest.raises(ValueError, match="Ident"):
            mschap.build_mschap2_response(
                ident=bad, peer_challenge=b"\x00" * 16, nt_response=b"\x00" * 24
            )

    def test_rejects_wrong_peer_challenge_size(self):
        with pytest.raises(ValueError, match="Peer challenge"):
            mschap.build_mschap2_response(
                ident=0,
                peer_challenge=b"\x00" * 15,
                nt_response=b"\x00" * 24,
            )

    def test_rejects_wrong_nt_response_size(self):
        with pytest.raises(ValueError, match="NT response"):
            mschap.build_mschap2_response(
                ident=0,
                peer_challenge=b"\x00" * 16,
                nt_response=b"\x00" * 25,
            )


class TestVerifyAuthenticatorResponse:
    def test_accepts_exact_match(self):
        assert mschap.verify_authenticator_response(
            RFC_PASSWORD,
            RFC_NT_RESPONSE,
            RFC_PEER_CHALLENGE,
            RFC_AUTH_CHALLENGE,
            RFC_USER,
            RFC_AUTHENTICATOR_RESPONSE,
        )

    def test_accepts_with_message_suffix(self):
        # MS-CHAP2-Success on the wire is usually "S=<auth> M=Welcome..."
        full = RFC_AUTHENTICATOR_RESPONSE + b" M=Welcome aboard"
        assert mschap.verify_authenticator_response(
            RFC_PASSWORD,
            RFC_NT_RESPONSE,
            RFC_PEER_CHALLENGE,
            RFC_AUTH_CHALLENGE,
            RFC_USER,
            full,
        )

    def test_accepts_with_leading_identifier_byte(self):
        # Some servers prepend the MS-CHAP-Identifier byte from RFC 2548
        # §2.3.3 — the helper must locate the "S=" marker rather than
        # rely on an absolute offset.
        with_ident = bytes([5]) + RFC_AUTHENTICATOR_RESPONSE
        assert mschap.verify_authenticator_response(
            RFC_PASSWORD,
            RFC_NT_RESPONSE,
            RFC_PEER_CHALLENGE,
            RFC_AUTH_CHALLENGE,
            RFC_USER,
            with_ident,
        )

    def test_rejects_wrong_authenticator(self):
        bogus = b"S=" + b"00" * 20
        assert not mschap.verify_authenticator_response(
            RFC_PASSWORD,
            RFC_NT_RESPONSE,
            RFC_PEER_CHALLENGE,
            RFC_AUTH_CHALLENGE,
            RFC_USER,
            bogus,
        )

    def test_rejects_missing_marker(self):
        assert not mschap.verify_authenticator_response(
            RFC_PASSWORD,
            RFC_NT_RESPONSE,
            RFC_PEER_CHALLENGE,
            RFC_AUTH_CHALLENGE,
            RFC_USER,
            b"no marker here",
        )

    def test_rejects_non_bytes_input(self):
        with pytest.raises(TypeError):
            mschap.verify_authenticator_response(
                RFC_PASSWORD,
                RFC_NT_RESPONSE,
                RFC_PEER_CHALLENGE,
                RFC_AUTH_CHALLENGE,
                RFC_USER,
                "not bytes",  # type: ignore[arg-type]
            )


class TestPrepareMschap2Request:
    def _make_pkt(self, **kwargs):
        # The helper only uses __contains__ / __delitem__ / __setitem__.
        return dict(kwargs)

    def test_replaces_user_password_with_vsas(self):
        pkt = self._make_pkt(**{"User-Password": [b"clientPass"]})

        nt_response = mschap.prepare_mschap2_request(
            pkt,
            user_name=RFC_USER,
            password=RFC_PASSWORD,
            authenticator_challenge=RFC_AUTH_CHALLENGE,
            peer_challenge=RFC_PEER_CHALLENGE,
        )

        assert "User-Password" not in pkt
        assert pkt["MS-CHAP-Challenge"] == RFC_AUTH_CHALLENGE
        assert pkt["MS-CHAP2-Response"][:2] == bytes([0, 0])  # ident, flags
        assert pkt["MS-CHAP2-Response"][2:18] == RFC_PEER_CHALLENGE
        assert pkt["MS-CHAP2-Response"][26:50] == RFC_NT_RESPONSE
        assert nt_response == RFC_NT_RESPONSE
