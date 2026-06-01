import hmac
import os
import struct
import pytest
import hashlib
from io import StringIO

from .base import TEST_ROOT_PATH

from collections import OrderedDict
from pyrad2 import packet
from pyrad2.client import Client
from pyrad2.dictionary import Dictionary
from pyrad2.constants import PacketType


class TestUtility:
    def testGenerateID(self):
        id = packet.create_id()
        assert isinstance(id, int)
        newid = packet.create_id()
        assert id != newid


class TestPacketConstruction:
    klass = packet.Packet

    @pytest.fixture(autouse=True)
    def _setup(self, simple_dictionary):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = simple_dictionary

    def testBasicConstructor(self):
        pkt = self.klass()
        assert isinstance(pkt.code, int)
        assert isinstance(pkt.id, int)
        assert isinstance(pkt.secret, bytes)

    def testNamedConstructor(self):
        pkt = self.klass(
            code=26,
            id=38,
            secret=b"secret",
            authenticator=b"authenticator",
            dict="fakedict",
        )
        assert pkt.code == 26
        assert pkt.id == 38
        assert pkt.secret == b"secret"
        assert pkt.authenticator == b"authenticator"
        assert pkt.dict == "fakedict"

    def testConstructWithDictionary(self):
        pkt = self.klass(dict=self.dict)
        assert pkt.dict is self.dict

    def testConstructorIgnoredParameters(self):
        marker = []
        pkt = self.klass(fd=marker)
        assert getattr(pkt, "fd", None) is not marker

    def testSecretMustBeBytestring(self):
        with pytest.raises(TypeError):
            self.klass(secret="secret")

    def testConstructorWithAttributes(self):
        pkt = self.klass(**{"Test-String": "this works", "dict": self.dict})
        assert pkt["Test-String"] == ["this works"]

    def testConstructorWithTlvAttribute(self):
        pkt = self.klass(
            **{"Test-Tlv-Str": "this works", "Test-Tlv-Int": 10, "dict": self.dict}
        )
        assert pkt["Test-Tlv"] == {"Test-Tlv-Str": ["this works"], "Test-Tlv-Int": [10]}


class TestPacket:
    @pytest.fixture(autouse=True)
    def _setup(self, full_dictionary):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = full_dictionary
        self.packet = packet.Packet(
            id=0, secret=b"secret", authenticator=b"01234567890ABCDEF", dict=self.dict
        )

    def _create_reply_with_duplicate_attributes(self, request):
        """
        Creates a reply to the given request with multiple instances of the
        same attribute that also do not appear sequentially in the list. Used
        to ensure that methods providing authenticator and
        Message-Authenticator verification can handle the case where multiple
        instances of an given attribute do not appear sequentially in the
        attributes list.
        """
        # Manually build the packet since using packet.Packet will always group
        # attributes of the same type together
        attributes = self._get_attribute_bytes("Test-String", "test")
        attributes += self._get_attribute_bytes("Test-Integer", 1)
        attributes += self._get_attribute_bytes("Test-String", "test")
        attributes += self._get_attribute_bytes("Message-Authenticator", 16 * b"\00")

        header = struct.pack(
            "!BBH", PacketType.AccessAccept, request.id, (20 + len(attributes))
        )

        # Calculate the Message-Authenticator and update the attribute
        hmac_constructor = hmac.new(request.secret, None, hashlib.md5)
        hmac_constructor.update(header + request.authenticator + attributes)
        updated_message_authenticator = hmac_constructor.digest()
        attributes = attributes.replace(b"\x00" * 16, updated_message_authenticator)

        # Calculate the response authenticator
        authenticator = hashlib.md5(
            header + request.authenticator + attributes + request.secret
        ).digest()

        reply_bytes = header + authenticator + attributes
        return packet.AuthPacket(packet=reply_bytes, dict=self.dict)

    def _get_attribute_bytes(self, attr_name, value):
        attr = self.dict.attributes[attr_name]
        attr_key = attr.code
        attr_value = packet.tools.encode_attr(attr.type, value)
        attr_len = len(attr_value) + 2
        return struct.pack("!BB", attr_key, attr_len) + attr_value

    def test_create_reply(self):
        reply = self.packet.create_reply(**{"Test-Integer": 10})
        assert reply.id == self.packet.id
        assert reply.secret == self.packet.secret
        assert reply.authenticator == self.packet.authenticator
        assert reply["Test-Integer"] == [10]

    def testAttributeAccess(self):
        self.packet["Test-Integer"] = 10
        assert self.packet["Test-Integer"] == [10]
        assert self.packet[3] == [b"\x00\x00\x00\x0a"]

        self.packet["Test-String"] = "dummy"
        assert self.packet["Test-String"] == ["dummy"]
        assert self.packet[1] == [b"dummy"]

    def testAttributeValueAccess(self):
        self.packet["Test-Integer"] = "Three"
        assert self.packet["Test-Integer"] == ["Three"]
        assert self.packet[3] == [b"\x00\x00\x00\x03"]

    def testVendorAttributeAccess(self):
        self.packet["Simplon-Number"] = 10
        assert self.packet["Simplon-Number"] == [10]
        assert self.packet[(16, 1)] == [b"\x00\x00\x00\x0a"]

        self.packet["Simplon-Number"] = "Four"
        assert self.packet["Simplon-Number"] == ["Four"]
        assert self.packet[(16, 1)] == [b"\x00\x00\x00\x04"]

    def testRawAttributeAccess(self):
        marker = [b""]
        self.packet[1] = marker
        assert self.packet[1] is marker
        self.packet[(16, 1)] = marker
        assert self.packet[(16, 1)] is marker

    def testEncryptedAttributes(self):
        self.packet["Test-Encrypted-String"] = "dummy"
        assert self.packet["Test-Encrypted-String"] == ["dummy"]

        self.packet["Test-Encrypted-Integer"] = 10
        assert self.packet["Test-Encrypted-Integer"] == [10]

    def testHasKey(self):
        assert not self.packet.has_key("Test-String")
        assert "Test-String" not in self.packet
        self.packet["Test-String"] = "dummy"
        assert self.packet.has_key("Test-String")
        assert self.packet.has_key(1)
        assert (1 in self.packet)

    def testHasKeyWithUnknownKey(self):
        assert not self.packet.has_key("Unknown-Attribute")
        assert "Unknown-Attribute" not in self.packet

    def testDelItem(self):
        self.packet["Test-String"] = "dummy"
        del self.packet["Test-String"]
        assert not self.packet.has_key("Test-String")
        self.packet["Test-String"] = "dummy"
        del self.packet[1]
        assert not self.packet.has_key("Test-String")

    def testKeys(self):
        assert self.packet.keys() == []
        self.packet["Test-String"] = "dummy"
        assert self.packet.keys() == ["Test-String"]
        self.packet["Test-Integer"] = 10
        assert self.packet.keys() == ["Test-String", "Test-Integer"]
        OrderedDict.__setitem__(self.packet, 12345, None)
        assert self.packet.keys() == ["Test-String", "Test-Integer", 12345]

    def test_create_authenticator(self):
        a = packet.Packet.create_authenticator()
        assert isinstance(a, bytes)
        assert len(a) == 16

        b = packet.Packet.create_authenticator()
        assert a != b

    def testGenerateID(self):
        id = self.packet.create_id()
        assert isinstance(id, int)
        newid = self.packet.create_id()
        assert id != newid

    def testReplyPacket(self):
        reply = self.packet.reply_packet()
        assert reply == (
            b"\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c"
            b"\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7"
        )

    def test_verify_reply(self):
        reply = self.packet.create_reply()
        assert self.packet.verify_reply(reply)

        reply.id += 1
        assert not self.packet.verify_reply(reply)
        reply.id = self.packet.id

        reply.secret = b"different"
        assert not self.packet.verify_reply(reply)
        reply.secret = self.packet.secret

        reply.authenticator = b"X" * 16
        assert not self.packet.verify_reply(reply)
        reply.authenticator = self.packet.authenticator

    def test_verify_reply_duplicate_attributes(self):
        reply = self._create_reply_with_duplicate_attributes(self.packet)
        assert self.packet.verify_reply(reply=reply, rawreply=reply.raw_packet)

    def test_verify_reply_enforce_ma_requires_reply_message_authenticator(self):
        request = packet.AuthPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=self.dict,
            message_authenticator=True,
        )
        request.request_packet()
        reply = request.create_reply()
        rawreply = reply.reply_packet()
        parsed_reply = request.create_reply(packet=rawreply)

        assert not request.verify_reply(parsed_reply, rawreply=rawreply, enforce_ma=True)

    def test_verify_reply_enforce_ma_validates_reply_message_authenticator(self):
        request = packet.AuthPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=self.dict,
        )
        reply = request.create_reply()
        reply.add_message_authenticator()
        rawreply = reply.reply_packet()
        parsed_reply = request.create_reply(packet=rawreply)

        assert request.verify_reply(parsed_reply, rawreply=rawreply, enforce_ma=True)

    def test_verify_reply_rejects_present_invalid_message_authenticator(self):
        request = packet.AuthPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=self.dict,
        )
        reply = request.create_reply()
        reply.add_message_authenticator()
        rawreply = bytearray(reply.reply_packet())

        # Corrupt only the Message-Authenticator, then recompute the response
        # authenticator so verify_reply must catch the MA failure specifically.
        offset = 20
        while offset < len(rawreply):
            attr_type = rawreply[offset]
            attr_len = rawreply[offset + 1]
            if attr_type == 80:
                rawreply[offset + 2] ^= 0xFF
                break
            offset += attr_len
        rawreply[4:20] = hashlib.md5(
            rawreply[0:4] + request.authenticator + rawreply[20:] + request.secret
        ).digest()
        parsed_reply = request.create_reply(packet=bytes(rawreply))

        assert not request.verify_reply(parsed_reply, rawreply=bytes(rawreply))

    def test_verify_message_authenticator(self):
        reply = self.packet.create_reply(
            **{
                "Test-String": "test",
                "Test-Integer": 3,
            }
        )
        reply.code = PacketType.AccessAccept
        reply.add_message_authenticator()
        reply._refresh_message_authenticator()
        assert reply.verify_message_authenticator(
            secret=b"secret",
            original_authenticator=self.packet.authenticator,
            original_code=self.packet.code,
        )

        assert not reply.verify_message_authenticator(
            secret=b"bad_secret",
            original_authenticator=self.packet.authenticator,
            original_code=self.packet.code,
        )

        assert not reply.verify_message_authenticator(
            secret=b"secret",
            original_authenticator=b"bad_authenticator",
            original_code=self.packet.code,
        )

    def testVerifyMessageAuthenticatorDuplicateAttributes(self):
        reply = self._create_reply_with_duplicate_attributes(self.packet)
        assert reply.verify_message_authenticator(
            secret=b"secret",
            original_authenticator=self.packet.authenticator,
            original_code=PacketType.AccessRequest,
        )

    def testPktEncodeAttribute(self):
        encode = self.packet._pkt_encode_attribute

        # Encode a normal attribute
        assert encode(1, b"value") == b"\x01\x07value"
        # Encode a vendor attribute
        assert encode((1, 2), b"value") == b"\x1a\x0d\x00\x00\x00\x01\x02\x07value"

    def testPktEncodeTlvAttribute(self):
        encode = self.packet._pkt_encode_tlv

        # Encode a normal tlv attribute
        assert (
            encode(4, {1: [b"value"], 2: [b"\x00\x00\x00\x02"]})
            == b"\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x02"
        )

        # Encode a normal tlv attribute with several sub attribute instances
        assert (
            encode(4, {1: [b"value", b"other"], 2: [b"\x00\x00\x00\x02"]})
            == b"\x04\x16\x01\x07value\x02\x06\x00\x00\x00\x02\x01\x07other"
        )
        # Encode a vendor tlv attribute
        assert (
            encode((16, 3), {1: [b"value"], 2: [b"\x00\x00\x00\x02"]})
            == b"\x1a\x15\x00\x00\x00\x10\x03\x0f\x01\x07value\x02\x06\x00\x00\x00\x02"
        )

    def testPktEncodeLongTlvAttribute(self):
        encode = self.packet._pkt_encode_tlv

        long_str = b"a" * 245
        # Encode a long tlv attribute - check it is split between AVPs
        assert (
            encode(4, {1: [b"value", long_str], 2: [b"\x00\x00\x00\x02"]})
            == b"\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x02\x04\xf9\x01\xf7" + long_str
        )

        # Encode a long vendor tlv attribute
        first_avp = (
            b"\x1a\x15\x00\x00\x00\x10\x03\x0f\x01\x07value\x02\x06\x00\x00\x00\x02"
        )
        second_avp = b"\x1a\xff\x00\x00\x00\x10\x03\xf9\x01\xf7" + long_str
        assert (
            encode((16, 3), {1: [b"value", long_str], 2: [b"\x00\x00\x00\x02"]})
            == first_avp + second_avp
        )

    def testPktEncodeAttributes(self):
        self.packet[1] = [b"value"]
        assert self.packet._pkt_encode_attributes() == b"\x01\x07value"

        self.packet.clear()
        self.packet[(16, 2)] = [b"value"]
        assert (
            self.packet._pkt_encode_attributes()
            == b"\x1a\x0d\x00\x00\x00\x10\x02\x07value"
        )

        self.packet.clear()
        self.packet[1] = [b"one", b"two", b"three"]
        assert (
            self.packet._pkt_encode_attributes()
            == b"\x01\x05one\x01\x05two\x01\x07three"
        )

        self.packet.clear()
        self.packet[1] = [b"value"]
        self.packet[(16, 2)] = [b"value"]
        assert (
            self.packet._pkt_encode_attributes()
            == b"\x01\x07value\x1a\x0d\x00\x00\x00\x10\x02\x07value"
        )

    def testPktDecodeVendorAttribute(self):
        decode = self.packet._pkt_decode_vendor_attribute

        # Non-RFC2865 recommended form
        assert decode(b"") == [(26, b"")]
        assert decode(b"12345") == [(26, b"12345")]

        # Almost RFC2865 recommended form: bad length value
        assert decode(b"\x00\x00\x00\x01\x02\x06value") == [
            (26, b"\x00\x00\x00\x01\x02\x06value")
        ]

        # Proper RFC2865 recommended form
        assert decode(b"\x00\x00\x00\x10\x02\x07value") == [((16, 2), b"value")]

    def testPktDecodeTlvAttribute(self):
        decode = self.packet._pkt_decode_tlv_attribute

        decode(4, b"\x01\x07value")
        assert self.packet[4] == {1: [b"value"]}

        # add another instance of the same sub attribute
        decode(4, b"\x01\x07other")
        assert self.packet[4] == {1: [b"value", b"other"]}

        # add a different sub attribute
        decode(4, b"\x02\x07\x00\x00\x00\x01")
        assert self.packet[4] == {1: [b"value", b"other"], 2: [b"\x00\x00\x00\x01"]}

    def testDecodePacketWithEmptyPacket(self):
        try:
            self.packet.decode_packet(b"")
        except packet.PacketError as e:
            assert "header is corrupt" in str(e)
        else:
            pytest.fail()

    def testDecodePacketWithInvalidLength(self):
        try:
            self.packet.decode_packet(b"\x00\x00\x00\x001234567890123456")
        except packet.PacketError as e:
            assert "invalid length" in str(e)
        else:
            pytest.fail()

    def testDecodePacketWithTooBigPacket(self):
        try:
            self.packet.decode_packet(b"\x00\x00\x24\x00" + (0x2400 - 4) * b"X")
        except packet.PacketError as e:
            assert "too long" in str(e)
        else:
            pytest.fail()

    def testDecodePacketWithPartialAttributes(self):
        try:
            self.packet.decode_packet(b"\x01\x02\x00\x151234567890123456\x00")
        except packet.PacketError as e:
            assert "header is corrupt" in str(e)
        else:
            pytest.fail()

    def testDecodePacketWithoutAttributes(self):
        self.packet.decode_packet(b"\x01\x02\x00\x141234567890123456")
        assert self.packet.code == 1
        assert self.packet.id == 2
        assert self.packet.authenticator == b"1234567890123456"
        assert self.packet.keys() == []

    def testDecodePacketWithBadAttribute(self):
        try:
            self.packet.decode_packet(b"\x01\x02\x00\x161234567890123456\x00\x01")
        except packet.PacketError as e:
            assert "too small" in str(e)
        else:
            pytest.fail()

    def testDecodePacketWithEmptyAttribute(self):
        self.packet.decode_packet(b"\x01\x02\x00\x161234567890123456\x01\x02")
        assert self.packet[1] == [b""]

    def testDecodePacketWithAttribute(self):
        self.packet.decode_packet(b"\x01\x02\x00\x1b1234567890123456\x01\x07value")
        assert self.packet[1] == [b"value"]

    def testDecodePacketWithUnknownAttribute(self):
        self.packet.decode_packet(b"\x01\x02\x00\x1b1234567890123456\x09\x07value")
        assert self.packet[9] == [b"value"]

    def testDecodePacketWithTlvAttribute(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x1d1234567890123456\x04\x09\x01\x07value"
        )
        assert self.packet[4] == {1: [b"value"]}

    def testDecodePacketIsTlvAttribute(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x1d1234567890123456\x04\x09\x01\x07value"
        )
        assert self.packet._pkt_is_tlv_attribute(4)

    def testDecodePacketWithVendorTlvAttribute(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x231234567890123456\x1a\x0f\x00\x00\x00\x10\x03\x09\x01\x07value"
        )
        assert self.packet[(16, 3)] == {1: [b"value"]}

    def testDecodePacketWithTlvAttributeWith2SubAttributes(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x231234567890123456\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x09"
        )
        assert self.packet[4] == {1: [b"value"], 2: [b"\x00\x00\x00\x09"]}

    def testDecodePacketWithSplitTlvAttribute(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x251234567890123456\x04\x09\x01\x07value\x04\x09\x02\x06\x00\x00\x00\x09"
        )
        assert self.packet[4] == {1: [b"value"], 2: [b"\x00\x00\x00\x09"]}

    def testDecodePacketWithMultiValuedAttribute(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x1e1234567890123456\x01\x05one\x01\x05two"
        )
        assert self.packet[1] == [b"one", b"two"]

    def testDecodePacketWithTwoAttributes(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x1e1234567890123456\x01\x05one\x01\x05two"
        )
        assert self.packet[1] == [b"one", b"two"]

    def testDecodePacketWithVendorAttribute(self):
        self.packet.decode_packet(b"\x01\x02\x00\x1b1234567890123456\x1a\x07value")
        assert self.packet[26] == [b"value"]

    def testEncodeKeyValues(self):
        assert self.packet._encode_key_values(1, "1234") == (1, "1234")

    def testEncodeKey(self):
        assert self.packet._encode_key(1) == 1

    def testadd_attribute(self):
        self.packet.add_attribute("Test-String", "1")
        assert self.packet["Test-String"] == ["1"]
        self.packet.add_attribute("Test-String", "1")
        assert self.packet["Test-String"] == ["1", "1"]
        self.packet.add_attribute("Test-String", ["2", "3"])
        assert self.packet["Test-String"] == ["1", "1", "2", "3"]


class TestAuthPacketConstruction(TestPacketConstruction):
    klass = packet.AuthPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        assert pkt.code == PacketType.AccessRequest


class TestStatusPacket:
    @pytest.fixture(autouse=True)
    def _setup(self, full_dictionary):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = full_dictionary
        self.packet = packet.StatusPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=self.dict,
        )

    def test_request_packet_includes_message_authenticator(self):
        rawpacket = self.packet.request_packet()
        parsed = packet.StatusPacket(packet=rawpacket, secret=b"secret", dict=self.dict)

        assert parsed.has_message_authenticator()
        assert parsed.verify_message_authenticator()

    def test_parse_packet_returns_status_packet(self):
        rawpacket = self.packet.request_packet()

        parsed = packet.parse_packet(rawpacket, b"secret", self.dict)

        assert isinstance(parsed, packet.StatusPacket)

    def test_validate_policy_requires_message_authenticator(self):
        rawpacket = (
            b"\x0c\x01\x00\x14"
            b"0123456789ABCDEF"
        )
        parsed = packet.StatusPacket(packet=rawpacket, secret=b"secret", dict=self.dict)

        with pytest.raises(packet.PacketError, match="Status-Server requires"):
            parsed.validate_message_authenticator_policy()

    def test_accounting_response_to_status_server_verifies_message_authenticator(self):
        reply = self.packet.create_reply(code=PacketType.AccountingResponse)
        reply.ensure_message_authenticator()
        rawreply = reply.reply_packet()
        parsed_reply = self.packet.create_reply(packet=rawreply)

        assert self.packet.verify_reply(parsed_reply, rawreply=rawreply)


class TestAuthPacket:
    @pytest.fixture(autouse=True)
    def _setup(self, full_dictionary):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = full_dictionary
        self.packet = packet.AuthPacket(
            id=0, secret=b"secret", authenticator=b"01234567890ABCDEF", dict=self.dict
        )

    def test_create_reply(self):
        reply = self.packet.create_reply(**{"Test-Integer": 10})
        assert reply.code == PacketType.AccessAccept
        assert reply.id == self.packet.id
        assert reply.secret == self.packet.secret
        assert reply.authenticator == self.packet.authenticator
        assert reply["Test-Integer"] == [10]

    def testRequestPacket(self):
        assert self.packet.request_packet() == b"\x01\x00\x00\x1401234567890ABCDE"

    def testRequestPacketCreatesAuthenticator(self):
        self.packet.authenticator = None
        self.packet.request_packet()
        assert self.packet.authenticator is not None

    def testRequestPacketCreatesID(self):
        self.packet.id = None
        self.packet.request_packet()
        assert self.packet.id is not None

    def testpw_cryptEmptyPassword(self):
        assert self.packet.pw_crypt("") == b""

    def testpw_cryptPassword(self):
        assert (
            self.packet.pw_crypt("Simplon")
            == b"\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01"
        )

    def testpw_cryptSetsAuthenticator(self):
        self.packet.authenticator = None
        self.packet.pw_crypt("")
        assert self.packet.authenticator is not None

    def testpw_decryptEmptyPassword(self):
        assert self.packet.pw_decrypt(b"") == ""

    def testpw_decryptPassword(self):
        assert (
            self.packet.pw_decrypt(b"\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01")
            == "Simplon"
        )


class TestAuthPacketChap:
    @pytest.fixture(autouse=True)
    def _setup(self, chap_dictionary):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = chap_dictionary
        # self.packet = packet.Packet(id=0, secret=b'secret',
        #                             dict=self.dict)
        self.client = Client(server="localhost", secret=b"secret", dict=self.dict)

    def testVerifyChapPasswd(self):
        chap_id = b"9"
        chap_challenge = b"987654321"
        chap_password = (
            chap_id + hashlib.md5(chap_id + b"test_password" + chap_challenge).digest()
        )
        pkt = self.client.create_auth_packet(
            code=PacketType.AccessChallenge,
            authenticator=b"ABCDEFG",
            User_Name="test_name",
            CHAP_Challenge=chap_challenge,
            CHAP_Password=chap_password,
        )
        assert pkt["CHAP-Challenge"][0] == chap_challenge
        assert pkt["CHAP-Password"][0] == chap_password
        assert pkt.verify_chap_passwd("test_password")


class TestAcctPacketConstruction(TestPacketConstruction):
    klass = packet.AcctPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        assert pkt.code == PacketType.AccountingRequest

    def testConstructorRawPacket(self):
        raw = (
            b"\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c"
            b"\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7"
        )
        pkt = self.klass(packet=raw)
        assert pkt.raw_packet == raw


class TestAcctPacket:
    @pytest.fixture(autouse=True)
    def _setup(self, full_dictionary):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = full_dictionary
        self.packet = packet.AcctPacket(
            id=0, secret=b"secret", authenticator=b"01234567890ABCDEF", dict=self.dict
        )

    def loadDict(self, filename="full"):
        return Dictionary(os.path.join(self.path, filename))

    def test_create_reply(self):
        reply = self.packet.create_reply(**{"Test-Integer": 10})
        assert reply.code == PacketType.AccountingResponse
        assert reply.id == self.packet.id
        assert reply.secret == self.packet.secret
        assert reply.authenticator == self.packet.authenticator
        assert reply["Test-Integer"] == [10]

    def test_verify_acct_request(self):
        rawpacket = self.packet.request_packet()
        pkt = packet.AcctPacket(secret=b"secret", packet=rawpacket)
        assert pkt.verify_acct_request()

        pkt.secret = b"different"
        assert not pkt.verify_acct_request()
        pkt.secret = b"secret"

        pkt.raw_packet = b"X" + pkt.raw_packet[1:]
        assert not pkt.verify_acct_request()

    def testRequestPacket(self):
        assert (
            self.packet.request_packet()
            == b"\x04\x00\x00\x14\x95\xdf\x90\xccbn\xfb\x15G!\x13\xea\xfa>6\x0f"
        )

    def testRequestPacketSetsId(self):
        self.packet.id = None
        self.packet.request_packet()
        assert self.packet.id is not None

    def testRealisticUnknownAttributes(self):
        """Test a realistic Accounting Packet from raw
        User-Name: [u'user@example.com']
        NAS-IP-Address: ['1.2.3.4']
        Service-Type: ['Framed-User']
        Framed-Protocol: ['NAS-Prompt-User']
        Framed-IP-Address: ['1.2.3.4']
        Acct-Status-Type: ['Interim-Update']
        Acct-Delay-Time: [0]
        Acct-Input-Octets: [1290826858]
        Acct-Output-Octets: [3551101035]
        Acct-Session-Id: [u'90dbd65a18b0a6c']
        Acct-Authentic: ['RADIUS']
        Acct-Session-Time: [769500]
        Acct-Input-Packets: [7403861]
        Acct-Output-Packets: [10928170]
        Acct-Link-Count: [1]
        Acct-Input-Gigawords: [0]
        Acct-Output-Gigawords: [2]
        Event-Timestamp: [1554155989]
        # vendor specific
        NAS-Port-Type: ['Virtual']
        (26, 594, 1): [u'UNKNOWN_PRODUCT']
        # implementation specific fields
        224: ['24P\x10\x00\x22\x96\xc9']
        228: ['\xfe\x99\xd0P']
        """
        raw = (
            b"\x04\x8e\x00\xc4\xb2\xf8z\xdb\xac\xfd9l\x9dI?E\x8c%\xe9"
            b"\xf5\x01\x12user@example.com\x04\x06\x01\x02\x03\x04\x06\x06"
            b"\x00\x00\x00\x02\x07\x06\x00\x00\x00\x07\x08\x06\x01\x02\x03"
            b"\x04(\x06\x00\x00\x00\x03)\x06\x00\x00\x00\x00*\x06L\xf0tj+"
            b"\x06\xd3\xa9\x80k,\x1190dbd65a18b0a6c-\x06\x00\x00\x00\x01."
            b"\x06\x00\x0b\xbd\xdc/\x06\x00p\xf9U0\x06\x00\xa6\xc0*3\x06"
            b"\x00\x00\x00\x014\x06\x00\x00\x00\x005\x06\x00\x00\x00\x027"
            b"\x06\\\xa2\x89\xd5=\x06\x00\x00\x00\x05\x1a\x17\x00\x00\x02R"
            b"\x01\x11UNKNOWN_PRODUCT\xe0\n24P\x10\x00\x22\x96\xc9\xe4\x06"
            b"\xfe\x99\xd0P"
        )
        pkt = packet.AcctPacket(dict=self.loadDict("realistic"), packet=raw)
        assert pkt.raw_packet == raw

        assert pkt.code == PacketType.AccountingRequest
        assert pkt["User-Name"] == ["user@example.com"]
        assert pkt["NAS-IP-Address"] == ["1.2.3.4"]
        assert pkt["Acct-Status-Type"] == ["Interim-Update"]
        assert pkt["Acct-Session-Id"] == ["90dbd65a18b0a6c"]
        assert pkt["Acct-Authentic"] == ["RADIUS"]

        # Unknown attributes preserved
        assert pkt[224][0] == b"24P\x10\x00\x22\x96\xc9"
        assert pkt[228][0] == b"\xfe\x99\xd0P"

        # Vendor unknown preserved
        assert pkt[(594, 1)] == [b"UNKNOWN_PRODUCT"]

        raw_no_authenticator = raw[:4] + b"\x00" * 16 + raw[20:]
        rebuilt = pkt.request_packet()
        rebuilt_no_authenticator = rebuilt[:4] + b"\x00" * 16 + rebuilt[20:]

        assert raw_no_authenticator == rebuilt_no_authenticator


class TestVendorFormatEncoding:
    """VSAs must honor the per-vendor ``(type_len, len_len)`` format."""

    def _make_packet(self, dict_source):
        d = Dictionary(StringIO(dict_source))
        return packet.Packet(
            id=0,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=d,
        )

    def test_default_format_unchanged(self):
        """Format (1,1) — RFC 2865 default — must produce the legacy layout."""
        pkt = self._make_packet(
            "VENDOR Cisco 9\nBEGIN-VENDOR Cisco\n"
            "ATTRIBUTE Cisco-AVPair 1 string\nEND-VENDOR Cisco\n"
        )
        encoded = pkt._pkt_encode_attribute((9, 1), b"hello")
        # [26][len][vendor_id=4][type=1][inner_len=7][value]
        assert encoded == b"\x1a\x0d\x00\x00\x00\x09\x01\x07hello"

    def test_format_4_2_encode_and_decode(self):
        """USR-style format=4,2 widens both type and length fields."""
        pkt = self._make_packet(
            "VENDOR Big 100 format=4,2\nBEGIN-VENDOR Big\n"
            "ATTRIBUTE Big-Attr 7 string\nEND-VENDOR Big\n"
        )
        encoded = pkt._pkt_encode_attribute((100, 7), b"hi")
        # [26][total_len=14][vendor=4][type=4 bytes 0x00000007][len=2 bytes 0x0008][hi]
        assert encoded == b"\x1a\x0e\x00\x00\x00\x64\x00\x00\x00\x07\x00\x08hi"

        # Decode round-trip: peel off the outer [26][len] header (2 bytes).
        decoded = pkt._pkt_decode_vendor_attribute(encoded[2:])
        assert decoded == [((100, 7), b"hi")]

    def test_format_2_1_encode_and_decode(self):
        pkt = self._make_packet(
            "VENDOR Mid 200 format=2,1\nBEGIN-VENDOR Mid\n"
            "ATTRIBUTE Mid-Attr 0x010f string\nEND-VENDOR Mid\n"
        )
        encoded = pkt._pkt_encode_attribute((200, 0x010F), b"abc")
        # Outer [26][len]; then vendor=4 bytes, type=2 bytes, length=1 byte, value=3 bytes.
        assert encoded[2:6] == b"\x00\x00\x00\xc8"  # vendor=200
        assert encoded[6:8] == b"\x01\x0f"  # 2-byte type
        assert encoded[8:9] == b"\x06"  # 1-byte length = type(2)+len(1)+value(3)
        assert encoded[9:] == b"abc"

        decoded = pkt._pkt_decode_vendor_attribute(encoded[2:])
        assert decoded == [((200, 0x010F), b"abc")]

    def test_format_4_0_no_length_field(self):
        """format=4,0 means the inner VSA fills the encapsulating AVP exactly."""
        pkt = self._make_packet(
            "VENDOR No-Len 429 format=4,0\nBEGIN-VENDOR No-Len\n"
            "ATTRIBUTE No-Len-Attr 5 string\nEND-VENDOR No-Len\n"
        )
        encoded = pkt._pkt_encode_attribute((429, 5), b"value")
        # No length field — value extends to the end of the buffer.
        assert encoded[2:6] == b"\x00\x00\x01\xad"  # vendor=429
        assert encoded[6:10] == b"\x00\x00\x00\x05"  # 4-byte type
        assert encoded[10:] == b"value"

        decoded = pkt._pkt_decode_vendor_attribute(encoded[2:])
        assert decoded == [((429, 5), b"value")]

    def test_decode_rejects_truncated_length(self):
        pkt = self._make_packet("VENDOR Foo 11\n")
        # length=99 but only 5 bytes of payload available.
        bad = b"\x00\x00\x00\x0b\x02\x63value"
        assert pkt._pkt_decode_vendor_attribute(bad) == [(26, bad)]


class TestConcatAttribute:
    """Attributes flagged with ``concat`` split on encode and merge on decode."""

    def _make_dict(self):
        return Dictionary(StringIO("ATTRIBUTE Long-Octets 30 octets concat\n"))

    def _make_packet(self):
        return packet.Packet(
            id=0,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=self._make_dict(),
        )

    def test_encode_splits_value_into_253_byte_chunks(self):
        pkt = self._make_packet()
        pkt[30] = [b"A" * 300]
        encoded = pkt._pkt_encode_attributes()
        # Expect two AVPs: [30][255][253 bytes A], then [30][49][47 bytes A]
        assert encoded[0] == 30
        assert encoded[1] == 255  # 253 value + 2 header
        assert encoded[2:255] == b"A" * 253
        rest = encoded[255:]
        assert rest[0] == 30
        assert rest[1] == 49  # 47 value + 2 header
        assert rest[2:] == b"A" * 47

    def test_encode_leaves_short_value_alone(self):
        pkt = self._make_packet()
        pkt[30] = [b"short"]
        encoded = pkt._pkt_encode_attributes()
        assert encoded == b"\x1e\x07short"

    def test_decode_merges_split_chunks(self):
        d = self._make_dict()
        pkt = packet.Packet(
            id=1, secret=b"secret", authenticator=b"0123456789ABCDEF", dict=d
        )
        chunk1 = b"A" * 253
        chunk2 = b"A" * 47
        attrs = (
            struct.pack("!BB", 30, len(chunk1) + 2)
            + chunk1
            + struct.pack("!BB", 30, len(chunk2) + 2)
            + chunk2
        )
        header = struct.pack("!BBH", 1, 1, 20 + len(attrs)) + b"0123456789ABCDEF"
        pkt.decode_packet(header + attrs)
        # After concat-merge there is exactly one entry of 300 bytes.
        assert len(pkt[30]) == 1
        assert pkt[30][0] == b"A" * 300

    def test_decode_does_not_merge_non_concat_attributes(self):
        d = Dictionary(StringIO("ATTRIBUTE Multi-String 31 string\n"))
        pkt = packet.Packet(
            id=1, secret=b"secret", authenticator=b"0123456789ABCDEF", dict=d
        )
        attrs = (
            struct.pack("!BB", 31, 5)
            + b"AAA"
            + struct.pack("!BB", 31, 5)
            + b"BBB"
        )
        header = struct.pack("!BBH", 1, 1, 20 + len(attrs)) + b"0123456789ABCDEF"
        pkt.decode_packet(header + attrs)
        # Two entries remain — concat must not affect plain string attributes.
        assert len(pkt[31]) == 2


class TestExtendedAttribute:
    """RFC 6929 extended attributes (types 241-244, no fragmentation)."""

    def _make_dict(self):
        return Dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-1 241 extended\n"
                "ATTRIBUTE Frag-Status 241.1 integer\n"
                "ATTRIBUTE Auth-Lifetime 241.2 integer\n"
            )
        )

    def _make_packet(self, dictionary=None):
        return packet.Packet(
            id=0,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=dictionary or self._make_dict(),
        )

    def test_encode_single_extended_avp(self):
        pkt = self._make_packet()
        pkt.add_attribute("Frag-Status", 5)
        encoded = pkt._pkt_encode_attributes()
        # [241][len=7][ext_type=1][4 bytes integer]
        assert encoded == b"\xf1\x07\x01\x00\x00\x00\x05"

    def test_decode_single_extended_avp(self):
        pkt = self._make_packet()
        attrs = b"\xf1\x07\x01\x00\x00\x00\x05"
        header = struct.pack("!BBH", 1, 1, 20 + len(attrs)) + b"0123456789ABCDEF"
        pkt.decode_packet(header + attrs)
        # Stored under parent code 241 as a sub-attribute dict.
        assert pkt[241] == {1: [b"\x00\x00\x00\x05"]}
        # And accessible by name via the parent.
        assert pkt["Extended-Attribute-1"] == {"Frag-Status": [5]}

    def test_roundtrip_multiple_sub_attributes(self):
        pkt = self._make_packet()
        pkt.add_attribute("Frag-Status", 5)
        pkt.add_attribute("Auth-Lifetime", 3600)
        encoded = pkt._pkt_encode_attributes()

        decoded = self._make_packet()
        header = struct.pack("!BBH", 1, 1, 20 + len(encoded)) + b"0123456789ABCDEF"
        decoded.decode_packet(header + encoded)
        assert decoded["Extended-Attribute-1"] == {
            "Frag-Status": [5],
            "Auth-Lifetime": [3600],
        }

    def test_encode_rejects_oversized_value(self):
        d = Dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-1 241 extended\n"
                "ATTRIBUTE Huge-Blob 241.7 octets\n"
            )
        )
        pkt = self._make_packet(d)
        # 253 bytes is too large for one extended AVP (cap is 252).
        pkt[241] = {7: [b"A" * 253]}
        with pytest.raises(ValueError):
            pkt._pkt_encode_attributes()


class TestLongExtendedAttribute:
    """RFC 6929 long-extended attributes (245-246), with fragmentation."""

    def _make_dict(self):
        return Dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-5 245 long-extended\n"
                "ATTRIBUTE WiMAX-Blob 245.1 octets\n"
            )
        )

    def _make_packet(self):
        return packet.Packet(
            id=0,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=self._make_dict(),
        )

    def test_encode_short_value_fits_single_fragment(self):
        pkt = self._make_packet()
        pkt.add_attribute("WiMAX-Blob", b"hello")
        encoded = pkt._pkt_encode_attributes()
        # [245][len=9][ext_type=1][flags=0][value]
        assert encoded == b"\xf5\x09\x01\x00hello"

    def test_encode_long_value_splits_with_more_flag(self):
        pkt = self._make_packet()
        # Max payload per fragment is 251 bytes, so 500 bytes → 2 fragments
        # (251 + 249), with More set on the first. The single-AVP encoder
        # rejects >253-byte octets, so set raw bytes on the parent dict
        # directly — that's the storage shape decode produces too.
        pkt[245] = {1: [b"A" * 500]}
        encoded = pkt._pkt_encode_attributes()

        # First fragment: [245][255][1][0x80][251 bytes A]
        first = encoded[:255]
        assert first[:4] == b"\xf5\xff\x01\x80"
        assert first[4:] == b"A" * 251

        # Second fragment: [245][253][1][0x00][249 bytes A]
        second = encoded[255:]
        assert second[:4] == b"\xf5\xfd\x01\x00"
        assert second[4:] == b"A" * 249

    def test_decode_reassembles_fragments(self):
        pkt = self._make_packet()
        # Manually build a 500-byte split payload like the encoder produces.
        payload = b"A" * 500
        first = (
            struct.pack("!BBBB", 245, 4 + 251, 1, 0x80) + payload[:251]
        )
        second = (
            struct.pack("!BBBB", 245, 4 + 249, 1, 0x00) + payload[251:]
        )
        attrs = first + second
        header = struct.pack("!BBH", 1, 1, 20 + len(attrs)) + b"0123456789ABCDEF"
        pkt.decode_packet(header + attrs)

        assert pkt["Extended-Attribute-5"] == {"WiMAX-Blob": [payload]}

    def test_roundtrip_large_value(self):
        pkt = self._make_packet()
        original = bytes(range(256)) * 5  # 1280 bytes — six fragments
        pkt[245] = {1: [original]}
        encoded = pkt._pkt_encode_attributes()

        decoded = self._make_packet()
        header = struct.pack("!BBH", 1, 1, 20 + len(encoded)) + b"0123456789ABCDEF"
        decoded.decode_packet(header + encoded)
        assert decoded[245] == {1: [original]}

    def test_decode_drops_orphan_fragment(self):
        # A fragment with More=1 that never sees its terminator must not
        # produce a partial value on the packet.
        pkt = self._make_packet()
        orphan = struct.pack("!BBBB", 245, 9, 1, 0x80) + b"hello"
        header = struct.pack("!BBH", 1, 1, 20 + len(orphan)) + b"0123456789ABCDEF"
        pkt.decode_packet(header + orphan)
        # No completed value was finalized.
        assert 245 not in pkt


class TestEvsAttribute:
    """RFC 6929 §2.3 Extended-Vendor-Specific (EVS) round-trips."""

    def _extended_dict(self):
        return Dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-1 241 extended\n"
                "ATTRIBUTE Extended-Vendor-Specific-1 241.26 evs\n"
                "VENDOR Example 12345\n"
                "BEGIN-VENDOR Example parent=Extended-Vendor-Specific-1\n"
                "ATTRIBUTE Example-Attr-1 1 string\n"
                "ATTRIBUTE Example-Attr-2 2 integer\n"
                "END-VENDOR Example\n"
            )
        )

    def _long_dict(self):
        return Dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-5 245 long-extended\n"
                "ATTRIBUTE Extended-Vendor-Specific-5 245.26 evs\n"
                "VENDOR Example 12345\n"
                "BEGIN-VENDOR Example parent=Extended-Vendor-Specific-5\n"
                "ATTRIBUTE Big-Blob 1 octets\n"
                "END-VENDOR Example\n"
            )
        )

    def _make_packet(self, dictionary):
        return packet.Packet(
            id=0,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=dictionary,
        )

    def test_encode_evs_inside_extended_wrapper(self):
        pkt = self._make_packet(self._extended_dict())
        pkt.add_attribute("Example-Attr-1", "hello")
        encoded = pkt._pkt_encode_attributes()
        # Wire: [241][len=13][ext=26][vendor_id=4 bytes][vsa_type=1][hello]
        assert encoded == b"\xf1\x0d\x1a\x00\x00\x30\x39\x01hello"

    def test_roundtrip_evs_under_extended(self):
        d = self._extended_dict()
        pkt = self._make_packet(d)
        pkt.add_attribute("Example-Attr-1", "hello")
        pkt.add_attribute("Example-Attr-2", 42)
        encoded = pkt._pkt_encode_attributes()

        decoded = self._make_packet(d)
        header = struct.pack("!BBH", 1, 1, 20 + len(encoded)) + b"0123456789ABCDEF"
        decoded.decode_packet(header + encoded)
        assert decoded["Example-Attr-1"] == ["hello"]
        assert decoded["Example-Attr-2"] == [42]
        # And the underlying storage is the flat 4-tuple key.
        assert decoded[(241, 26, 12345, 1)] == [b"hello"]

    def test_encode_evs_rejects_oversize_under_extended(self):
        d = self._extended_dict()
        pkt = self._make_packet(d)
        # 248 bytes exceeds the 247-byte cap for extended EVS.
        pkt[(241, 26, 12345, 1)] = [b"A" * 248]
        with pytest.raises(ValueError):
            pkt._pkt_encode_attributes()

    def test_long_extended_evs_fragments_and_reassembles(self):
        d = self._long_dict()
        pkt = self._make_packet(d)
        # Each long-extended EVS fragment carries 246 bytes of value, so
        # 600 bytes splits into three fragments (246 + 246 + 108).
        original = b"X" * 600
        pkt[(245, 26, 12345, 1)] = [original]
        encoded = pkt._pkt_encode_attributes()

        # First fragment header: parent=245, len=255, ext=26, more=0x80
        assert encoded[:4] == b"\xf5\xff\x1a\x80"
        # Then vendor_id 4 bytes + vsa_type 1 byte + 246 bytes payload.
        assert encoded[4:9] == b"\x00\x00\x30\x39\x01"
        assert encoded[9:255] == b"X" * 246

        # Reassemble through decode.
        decoded = self._make_packet(d)
        header = struct.pack("!BBH", 1, 1, 20 + len(encoded)) + b"0123456789ABCDEF"
        decoded.decode_packet(header + encoded)
        assert decoded[(245, 26, 12345, 1)] == [original]
        assert decoded["Big-Blob"] == [original]

    def test_extended_decode_falls_back_when_no_evs_marker(self):
        # An extended attribute at slot 26 with no EVS marker in the dict
        # must still decode as a regular extended sub-attribute, not EVS.
        d = Dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-1 241 extended\n"
                "ATTRIBUTE Plain-Sub 241.26 octets\n"
            )
        )
        pkt = self._make_packet(d)
        # [241][len=10][ext=26][7 bytes payload]
        attrs = b"\xf1\x0a\x1a" + b"payload"
        header = struct.pack("!BBH", 1, 1, 20 + len(attrs)) + b"0123456789ABCDEF"
        pkt.decode_packet(header + attrs)
        # Stored as a normal extended sub-attribute, not split as EVS.
        assert pkt[241] == {26: [b"payload"]}


class TestBlastRadiusHardening:
    """Regression coverage for the C1/C4 security defaults.

    C1: every MAC/MD5 compare in the verify path goes through
        ``hmac.compare_digest`` rather than ``==``.
    C4: ``salt_crypt`` must never seed the keystream with an all-zero
        Request Authenticator, and the server must reject Access-Request
        packets whose Authenticator is all-zero.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, full_dictionary):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = full_dictionary

    def test_verify_paths_use_constant_time_compare(self):
        import pyrad2.packet as packet_mod

        calls: list[tuple[bytes, bytes]] = []
        real_compare_digest = hmac.compare_digest

        def spy(a, b):
            calls.append((bytes(a), bytes(b)))
            return real_compare_digest(a, b)

        request = packet.AuthPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=self.dict,
        )
        request.add_message_authenticator()
        request.raw_packet = request.request_packet()
        reply = request.create_reply()
        reply.add_message_authenticator()
        rawreply = reply.reply_packet()

        original = packet_mod.hmac.compare_digest
        packet_mod.hmac.compare_digest = spy
        try:
            # verify_reply runs Response Authenticator MD5 compare and
            # Message-Authenticator HMAC compare; both must go through
            # compare_digest, not ==.
            assert request.verify_reply(
                reply=request.create_reply(packet=rawreply),
                rawreply=rawreply,
                enforce_ma=True,
            )
        finally:
            packet_mod.hmac.compare_digest = original

        # We expect at least two compare_digest invocations: one for the
        # Response Authenticator MD5 and one for the reply's
        # Message-Authenticator HMAC.
        assert len(calls) >= 2

    def test_salt_crypt_seeds_random_authenticator(self):
        pkt = packet.AuthPacket(id=1, secret=b"secret", dict=self.dict)
        assert pkt.authenticator is None

        encoded = pkt.salt_crypt(b"hunter2")

        # Authenticator must be seeded by salt_crypt and must not be the
        # all-zero fallback that used to leak keystream determinism.
        assert pkt.authenticator is not None
        assert pkt.authenticator is not None
        assert len(pkt.authenticator) == 16
        assert pkt.authenticator != b"\x00" * 16
        # Sanity: ciphertext layout (2-byte salt + payload) is intact.
        assert len(encoded) % 16 == 2

    def test_verify_auth_request_rejects_zero_authenticator(self):
        """Server-side guard: a v1.0 Access-Request with an all-zero
        Authenticator is rejected (RFC 2865 §3 requires unpredictability;
        an all-zero value lets an attacker recover salt-encrypted attrs)."""
        attrs = b""
        header = struct.pack("!BBH16s", PacketType.AccessRequest, 1, 20, b"\x00" * 16)
        pkt = packet.AuthPacket(
            packet=header + attrs, secret=b"secret", dict=self.dict
        )
        assert not pkt.verify_auth_request()

    def test_verify_auth_request_accepts_random_authenticator(self):
        attrs = b""
        header = struct.pack(
            "!BBH16s", PacketType.AccessRequest, 1, 20, b"0123456789ABCDEF"
        )
        pkt = packet.AuthPacket(
            packet=header + attrs, secret=b"secret", dict=self.dict
        )
        assert pkt.verify_auth_request()
