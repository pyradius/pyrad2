import select
import socket

import pytest

from pyrad2.client import Client, Timeout
from pyrad2.constants import PacketType
from pyrad2.packet import AcctPacket, AuthPacket, CoAPacket, StatusPacket

from .mock import MockPacket, MockPoll, MockSocket

BIND_IP = "127.0.0.1"
BIND_PORT = 53535


class TestConstruction:
    def setup_method(self):
        self.server = object()

    def test_simple_construction(self):
        client = Client(self.server)
        assert client.server is self.server
        assert client.authport == 1812
        assert client.acctport == 1813
        assert client.secret == b""
        assert client.retries == 3
        assert client.timeout == 5
        assert client.dict is None

    def test_parameter_order(self):
        marker = object()
        client = Client(self.server, 123, 456, 789, "secret", marker)
        assert client.server is self.server
        assert client.authport == 123
        assert client.acctport == 456
        assert client.coaport == 789
        assert client.secret == "secret"
        assert client.dict is marker

    def test_named_parameters(self):
        marker = object()
        client = Client(
            server=self.server,
            authport=123,
            acctport=456,
            secret="secret",
            dict=marker,
        )
        assert client.server is self.server
        assert client.authport == 123
        assert client.acctport == 456
        assert client.secret == "secret"
        assert client.dict is marker


class TestSocket:
    def setup_method(self):
        self.server = object()
        self.client = Client(self.server)
        self._orgsocket = socket.socket
        socket.socket = MockSocket

    def teardown_method(self):
        socket.socket = self._orgsocket
        # ``MockPoll.results`` is a class attribute; tests below assign to
        # it and the original suite happened to be insulated by execution
        # order. Clear it explicitly so we don't leak state into other
        # files (e.g. ``test_server.py::TestServerRun`` would otherwise
        # see ``(1, POLLIN)`` left over and KeyError on an empty fdmap).
        MockPoll.results = []

    def test_reopen(self):
        self.client._socket_open()
        sock = self.client._socket
        self.client._socket_open()
        assert sock is self.client._socket

    def test_bind(self):
        self.client.bind((BIND_IP, BIND_PORT))
        assert self.client._socket.address == (BIND_IP, BIND_PORT)
        assert self.client._socket.options == [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ]

    def test_bind_closes_socket(self):
        s = MockSocket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client._socket = s
        self.client._poll = MockPoll()
        self.client.bind((BIND_IP, BIND_PORT))
        assert s.closed is True

    def test_send_packet(self):
        def MockSend(self, pkt, port):
            self._mock_pkt = pkt
            self._mock_port = port

        _send_packet = Client._send_packet
        Client._send_packet = MockSend

        try:
            self.client.send_packet(AuthPacket())
            assert self.client._mock_port == self.client.authport

            self.client.send_packet(AcctPacket())
            assert self.client._mock_port == self.client.acctport

            # CoA packets must route to the CoA port, not auth/acct.
            self.client.send_packet(CoAPacket())
            assert self.client._mock_port == self.client.coaport

            # Status-Server packets default to the auth port.
            self.client.send_packet(StatusPacket())
            assert self.client._mock_port == self.client.authport
        finally:
            Client._send_packet = _send_packet

    def test_no_retries(self):
        self.client.retries = 0
        with pytest.raises(Timeout):
            self.client._send_packet(None, None)

    def test_single_retry(self):
        self.client.retries = 1
        self.client.timeout = 0
        packet = MockPacket(PacketType.AccessRequest)
        with pytest.raises(Timeout):
            self.client._send_packet(packet, 432)
        assert self.client._socket.output == [("request packet", (self.server, 432))]

    def test_double_retry(self):
        self.client.retries = 2
        self.client.timeout = 0
        packet = MockPacket(PacketType.AccessRequest)
        with pytest.raises(Timeout):
            self.client._send_packet(packet, 432)
        assert self.client._socket.output == [
            ("request packet", (self.server, 432)),
            ("request packet", (self.server, 432)),
        ]

    def test_auth_delay(self):
        self.client.retries = 2
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"valid reply")
        packet = MockPacket(PacketType.AccessRequest)
        with pytest.raises(Timeout):
            self.client._send_packet(packet, 432)
        assert "Acct-Delay-Time" not in packet

    def test_single_account_delay(self):
        self.client.retries = 2
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"valid reply")
        packet = MockPacket(PacketType.AccountingRequest)
        with pytest.raises(Timeout):
            self.client._send_packet(packet, 432)
        assert packet["Acct-Delay-Time"] == [1]

    def test_double_account_delay(self):
        self.client.retries = 3
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"valid reply")
        packet = MockPacket(PacketType.AccountingRequest)
        with pytest.raises(Timeout):
            self.client._send_packet(packet, 432)
        assert packet["Acct-Delay-Time"] == [2]

    def test_ignore_packet_error(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"valid reply")
        packet = MockPacket(PacketType.AccountingRequest, verify=True, error=True)
        with pytest.raises(Timeout):
            self.client._send_packet(packet, 432)

    def test_valid_reply(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"valid reply")
        self.client._poll = MockPoll()
        MockPoll.results = [(1, select.POLLIN)]
        packet = MockPacket(PacketType.AccountingRequest, verify=True)
        reply = self.client._send_packet(packet, 432)
        assert reply is packet.reply

    def test_invalid_reply(self):
        self.client.retries = 1
        self.client.timeout = 1
        self.client._socket = MockSocket(1, 2, b"invalid reply")
        MockPoll.results = [(1, select.POLLIN)]
        packet = MockPacket(PacketType.AccountingRequest, verify=False)
        with pytest.raises(Timeout):
            self.client._send_packet(packet, 432)


class TestOther:
    def setup_method(self):
        self.server = object()
        self.client = Client(self.server, secret=b"zeer geheim")

    def test_auth_packet(self):
        packet = self.client.create_auth_packet(id=15)
        assert isinstance(packet, AuthPacket)
        assert packet.dict is self.client.dict
        assert packet.id == 15
        assert packet.secret == b"zeer geheim"

    def test_prepare_outgoing_auth_packet_adds_ma_for_eap_message(
        self, full_dictionary
    ):
        client = Client(self.server, secret=b"secret", dict=full_dictionary)
        packet = client.create_auth_packet(id=15)
        packet[79] = [b"\x02\x01\x00\x05\x01"]

        client._prepare_outgoing_packet(packet)

        assert packet.has_message_authenticator()

    def test_status_packet(self):
        packet = self.client.create_status_packet(id=15)
        assert isinstance(packet, StatusPacket)
        assert packet.dict is self.client.dict
        assert packet.id == 15
        assert packet.secret == b"zeer geheim"

    def test_prepare_outgoing_status_packet_adds_ma(self, full_dictionary):
        client = Client(self.server, secret=b"secret", dict=full_dictionary)
        packet = client.create_status_packet(id=15)

        client._prepare_outgoing_packet(packet)

        assert packet.has_message_authenticator()

    def test_create_acct_packet(self):
        packet = self.client.create_acct_packet(id=15)
        assert isinstance(packet, AcctPacket)
        assert packet.dict is self.client.dict
        assert packet.id == 15
        assert packet.secret == b"zeer geheim"
