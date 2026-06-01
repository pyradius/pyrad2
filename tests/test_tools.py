import ssl

import pytest

from pyrad2 import tools

from .base import TEST_ROOT_PATH


# 253-byte payload (the AVP max) and 254-byte payload (one byte over).
# ``encode_octets`` checks the hex literal's total length, so the
# reject case needs to be 254 hex pairs even though the underlying
# byte ceiling is 253.
_LONG_HEX_253 = "AB" * 253
_LONG_HEX_254 = "AB" * 254
_LONG_BYTES_253 = bytes.fromhex(_LONG_HEX_253)


class TestEncoding:
    def test_string_encoding(self):
        with pytest.raises(ValueError):
            tools.encode_string("x" * 254)
        assert tools.encode_string("1234567890") == b"1234567890"

    def test_invalid_string_encoding_raises_type_error(self):
        with pytest.raises(TypeError):
            tools.encode_string(1)

    def test_address_encoding(self):
        with pytest.raises((ValueError, Exception)):
            tools.encode_address("TEST123")
        assert tools.encode_address("192.168.0.255") == b"\xc0\xa8\x00\xff"

    def test_invalid_address_encoding_raises_type_error(self):
        with pytest.raises(TypeError):
            tools.encode_address(1)

    def test_integer_encoding(self):
        assert tools.encode_integer(0x01020304) == b"\x01\x02\x03\x04"

    def test_integer64_encoding(self):
        assert tools.encode_integer64(0xFFFFFFFFFFFFFFFF) == b"\xff" * 8

    def test_unsigned_integer_encoding(self):
        assert tools.encode_integer(0xFFFFFFFF) == b"\xff\xff\xff\xff"

    def test_invalid_integer_encoding_raises_type_error(self):
        with pytest.raises(TypeError):
            tools.encode_integer("ONE")

    def test_date_encoding(self):
        assert tools.encode_date(0x01020304) == b"\x01\x02\x03\x04"

    def test_invalid_data_encoding_raises_type_error(self):
        with pytest.raises(TypeError):
            tools.encode_date("1")

    def test_encode_ascend_binary(self):
        assert tools.encode_ascend_binary(
            "family=ipv4 action=discard direction=in dst=10.10.255.254/32"
        ) == (
            b"\x01\x00\x01\x00\x00\x00\x00\x00\n\n\xff\xfe\x00 "
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00"
        )

    def test_string_decoding(self):
        assert tools.decode_string(b"1234567890") == "1234567890"

    def test_address_decoding(self):
        assert tools.decode_address(b"\xc0\xa8\x00\xff") == "192.168.0.255"

    def test_integer_decoding(self):
        assert tools.decode_integer(b"\x01\x02\x03\x04") == 0x01020304

    def test_integer64_decoding(self):
        assert tools.decode_integer64(b"\xff" * 8) == 0xFFFFFFFFFFFFFFFF

    def test_date_decoding(self):
        assert tools.decode_date(b"\x01\x02\x03\x04") == 0x01020304

    def test_octets_encoding(self):
        assert tools.encode_octets("0x01020304") == b"\x01\x02\x03\x04"
        assert tools.encode_octets(b"0x01020304") == b"\x01\x02\x03\x04"
        assert tools.encode_octets("16909060") == b"\x01\x02\x03\x04"
        # 253 byte payload sits exactly at the AVP ceiling.
        assert tools.encode_octets("0x" + _LONG_HEX_253) == _LONG_BYTES_253
        with pytest.raises(
            ValueError, match="Can only encode strings of <= 253 characters"
        ):
            tools.encode_octets("0x" + _LONG_HEX_254)

    def test_ifid_encoding_roundtrip(self):
        text = "0011:2233:4455:6677"
        raw = tools.encode_ifid(text)
        assert raw == b"\x00\x11\x22\x33\x44\x55\x66\x77"
        assert tools.decode_ifid(raw) == text

    def test_ifid_encoding_passes_through_8_byte_input(self):
        raw = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        assert tools.encode_ifid(raw) == raw

    def test_ifid_encoding_rejects_bad_input(self):
        with pytest.raises(ValueError):
            tools.encode_ifid("0011:2233:4455")
        with pytest.raises(ValueError):
            tools.encode_ifid("zzzz:0000:0000:0000")
        with pytest.raises(ValueError):
            tools.encode_ifid("10000:0:0:0")
        with pytest.raises(ValueError):
            tools.encode_ifid(b"\x00" * 4)
        with pytest.raises(TypeError):
            tools.encode_ifid(42)

    def test_ifid_decoding_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            tools.decode_ifid(b"\x00" * 6)

    def test_ether_encoding_roundtrip(self):
        text = "aa:bb:cc:dd:ee:ff"
        raw = tools.encode_ether(text)
        assert raw == b"\xaa\xbb\xcc\xdd\xee\xff"
        assert tools.decode_ether(raw) == text

    def test_ether_encoding_accepts_hyphen_separator(self):
        assert tools.encode_ether("AA-BB-CC-DD-EE-FF") == b"\xaa\xbb\xcc\xdd\xee\xff"

    def test_ether_encoding_passes_through_6_byte_input(self):
        raw = b"\x01\x02\x03\x04\x05\x06"
        assert tools.encode_ether(raw) == raw

    def test_ether_encoding_rejects_bad_input(self):
        with pytest.raises(ValueError):
            tools.encode_ether("aa:bb:cc:dd:ee")
        with pytest.raises(ValueError):
            tools.encode_ether("zz:bb:cc:dd:ee:ff")
        with pytest.raises(TypeError):
            tools.encode_ether(42)

    def test_ether_decoding_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            tools.decode_ether(b"\x00" * 4)

    def test_unknown_type_encoding(self):
        with pytest.raises(ValueError):
            tools.encode_attr("unknown", None)

    def test_unknown_type_decoding(self):
        with pytest.raises(ValueError):
            tools.decode_attr("unknown", None)

    def test_normalize_cert_fingerprint(self):
        fingerprint = "SHA256:AA:BB " + ("cc" * 29) + "dd"
        assert tools.normalize_cert_fingerprint(fingerprint) == (
            "aabb" + ("cc" * 29) + "dd"
        )

    def test_normalize_cert_fingerprint_rejects_invalid_values(self):
        with pytest.raises(ValueError):
            tools.normalize_cert_fingerprint("abc")
        with pytest.raises(ValueError):
            tools.normalize_cert_fingerprint("z" * 64)

    def test_cert_fingerprint_matches_allowlist(self):
        with open(f"{TEST_ROOT_PATH}/certs/client/client.cert.pem") as cert_file:
            cert = ssl.PEM_cert_to_DER_cert(cert_file.read())

        fingerprint = tools.get_cert_fingerprint(cert)

        assert tools.cert_fingerprint_matches(cert, {fingerprint}) is True
        assert tools.cert_fingerprint_matches(cert, {"0" * 64}) is False

    def test_encode_function(self):
        assert tools.encode_attr("string", "string") == b"string"
        assert tools.encode_attr("octets", b"string") == b"string"
        assert tools.encode_attr("ipaddr", "192.168.0.255") == b"\xc0\xa8\x00\xff"
        assert tools.encode_attr("integer", 0x01020304) == b"\x01\x02\x03\x04"
        assert tools.encode_attr("date", 0x01020304) == b"\x01\x02\x03\x04"
        assert tools.encode_attr("integer64", 0xFFFFFFFFFFFFFFFF) == b"\xff" * 8
        assert (
            tools.encode_attr("ifid", "0011:2233:4455:6677")
            == b"\x00\x11\x22\x33\x44\x55\x66\x77"
        )
        assert (
            tools.encode_attr("ether", "aa:bb:cc:dd:ee:ff")
            == b"\xaa\xbb\xcc\xdd\xee\xff"
        )

    def test_decode_function(self):
        assert tools.decode_attr("string", b"string") == "string"
        assert tools.encode_attr("octets", b"string") == b"string"
        assert tools.decode_attr("ipaddr", b"\xc0\xa8\x00\xff") == "192.168.0.255"
        assert tools.decode_attr("integer", b"\x01\x02\x03\x04") == 0x01020304
        assert tools.decode_attr("integer64", b"\xff" * 8) == 0xFFFFFFFFFFFFFFFF
        assert tools.decode_attr("date", b"\x01\x02\x03\x04") == 0x01020304
        assert (
            tools.decode_attr("ifid", b"\x00\x11\x22\x33\x44\x55\x66\x77")
            == "0011:2233:4455:6677"
        )
        assert (
            tools.decode_attr("ether", b"\xaa\xbb\xcc\xdd\xee\xff")
            == "aa:bb:cc:dd:ee:ff"
        )
