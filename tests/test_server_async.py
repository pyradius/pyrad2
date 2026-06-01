from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrad2 import packet
from pyrad2.constants import ErrorCause, PacketType
from pyrad2.exceptions import PacketError
from pyrad2.server import RemoteHost
from pyrad2.server_async import DatagramProtocolServer, ServerAsync, ServerType

from .base import DummyServer, capture_logs


class AuthAcctOnlyServer(ServerAsync):
    def handle_auth_packet(self, protocol, pkt, addr):
        self.auth_called = True

    def handle_acct_packet(self, protocol, pkt, addr):
        self.acct_called = True


class TestDatagramProtocolServer:
    def setup_method(self):
        self.server = DummyServer(debug=True)
        self.remote_host = RemoteHost("127.0.0.1", b"secret", "name")
        self.hosts = {"127.0.0.1": self.remote_host}
        self.protocol = DatagramProtocolServer(
            ip="127.0.0.1",
            port=1812,
            server=self.server,
            server_type=ServerType.Auth,
            hosts=self.hosts,
            request_callback=self.server._request_handler,
        )
        self.transport = MagicMock()

    def test_connection_made(self):
        with capture_logs() as output:
            self.protocol.connection_made(self.transport)

        assert len(output) == 1
        assert self.protocol.transport == self.transport

    def test_connection_lost(self):
        with capture_logs() as output:
            self.protocol.connection_lost(None)

        assert len(output) == 1

    def test_error_received(self):
        self.protocol.connection_made(self.transport)
        with capture_logs() as output:
            self.protocol.error_received(Exception("Test error"))

        assert len(output) == 1

    def test_send_response(self):
        self.protocol.connection_made(self.transport)
        mock_packet = MagicMock()
        mock_packet.reply_packet.return_value = b"response"
        self.protocol.send_response(mock_packet, ("127.0.0.1", 12345))
        self.transport.sendto.assert_called_once_with(
            b"response", ("127.0.0.1", 12345)
        )

    def test_auth_status_server_replies_without_callback(self, full_dictionary):
        self.server.dict = full_dictionary
        request = packet.StatusPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=full_dictionary,
        )
        self.protocol.connection_made(self.transport)
        self.protocol.request_callback = MagicMock()

        self.protocol.datagram_received(
            request.request_packet(), ("127.0.0.1", 12345)
        )

        self.protocol.request_callback.assert_not_called()
        rawreply = self.transport.sendto.call_args.args[0]
        reply = request.create_reply(packet=rawreply)
        assert reply.code == PacketType.AccessAccept
        assert request.verify_reply(reply, rawreply=rawreply)

    def test_accounting_status_server_replies_with_accounting_response(
        self, full_dictionary
    ):
        dictionary = full_dictionary
        server = DummyServer(dictionary=dictionary)
        remote_host = RemoteHost("127.0.0.1", b"secret", "name")
        protocol = DatagramProtocolServer(
            ip="127.0.0.1",
            port=1813,
            server=server,
            server_type=ServerType.Acct,
            hosts={"127.0.0.1": remote_host},
            request_callback=MagicMock(),
        )
        protocol.connection_made(self.transport)
        request = packet.StatusPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=dictionary,
        )

        protocol.datagram_received(request.request_packet(), ("127.0.0.1", 12345))

        rawreply = self.transport.sendto.call_args.args[0]
        reply = request.create_reply(packet=rawreply)
        assert reply.code == PacketType.AccountingResponse
        assert request.verify_reply(reply, rawreply=rawreply)


class TestServerAsync:
    """Mix of sync and async tests on ServerAsync — pytest-asyncio in
    ``auto`` mode handles the ``async def`` ones without per-test markers."""

    def setup_method(self):
        self.server = DummyServer()
        self.server.dict = MagicMock()
        self.remote_host = RemoteHost("127.0.0.1", b"secret", "name")
        self.server.hosts = {"127.0.0.1": self.remote_host}

    @patch.object(DummyServer, "_start_transport", new_callable=AsyncMock)
    async def test_initialize_transports(self, mock_start_transport):
        await self.server.initialize_transports(enable_auth=True)
        mock_start_transport.assert_awaited_once()

    @patch("pyrad2.server_async.DatagramProtocolServer")
    async def test_deinitialize_transports(self, mock_protocol_cls):
        mock_proto = AsyncMock()
        self.server.auth_protocols = [mock_proto]
        await self.server.deinitialize_transports()
        mock_proto.close_transport.assert_awaited_once()
        assert self.server.auth_protocols == []

    def test_create_reply_packet(self):
        server = DummyServer()
        pkt = MagicMock()
        server.create_reply_packet(pkt, Attr1="value")
        pkt.create_reply.assert_called_once_with(Attr1="value")

    def test_create_reply_packet_requires_packet(self):
        server = DummyServer()
        with pytest.raises(ValueError, match="Missing packet to reply to"):
            server.create_reply_packet()

    def test_message_authenticator_policy_rejects_eap_without_ma(
        self, full_dictionary
    ):
        dictionary = full_dictionary
        # require_message_authenticator=False isolates the EAP-specific
        # policy gate (otherwise the general BlastRADIUS rule fires first).
        server = DummyServer(
            dictionary=dictionary, require_message_authenticator=False
        )
        pkt = packet.AuthPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=dictionary,
        )
        pkt[79] = [b"\x02\x01\x00\x05\x01"]
        parsed = packet.AuthPacket(
            packet=pkt.request_packet(), secret=b"secret", dict=dictionary
        )

        with pytest.raises(PacketError, match="EAP-Message requires"):
            server.validate_message_authenticator_policy(parsed)

    def test_create_reply_packet_adds_ma_when_policy_requires_it(
        self, full_dictionary
    ):
        dictionary = full_dictionary
        server = DummyServer(
            dictionary=dictionary,
            require_message_authenticator=True,
        )
        pkt = packet.AuthPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=dictionary,
        )

        reply = server.create_reply_packet(pkt)

        assert reply.has_message_authenticator()

    def test_request_handler_auth(self):
        mock_pkt = MagicMock(code=PacketType.AccessRequest)
        proto = MagicMock(server_type=ServerType.Auth, ip="127.0.0.1", port=1812)
        self.server._request_handler(proto, mock_pkt, "127.0.0.1")
        assert self.server.auth_called

    def test_request_handler_acct(self):
        mock_pkt = MagicMock(code=PacketType.AccountingRequest)
        proto = MagicMock(server_type=ServerType.Acct)
        self.server._request_handler(proto, mock_pkt, "127.0.0.1")
        assert self.server.acct_called

    def test_request_handler_coa(self):
        mock_pkt = MagicMock(code=PacketType.CoARequest)
        proto = MagicMock(server_type=ServerType.Coa)
        self.server._request_handler(proto, mock_pkt, "127.0.0.1")
        assert self.server.coa_called

    def test_request_handler_disconnect(self):
        mock_pkt = MagicMock(code=PacketType.DisconnectRequest)
        proto = MagicMock(server_type=ServerType.Coa)
        self.server._request_handler(proto, mock_pkt, "127.0.0.1")
        assert self.server.disconnect_called

    def test_auth_acct_only_subclass_is_concrete(self):
        server = AuthAcctOnlyServer()

        assert isinstance(server, ServerAsync)

    def test_default_coa_handler_sends_nak(self, full_dictionary):
        server = AuthAcctOnlyServer()
        protocol = MagicMock()
        request = packet.CoAPacket(
            code=PacketType.CoARequest,
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=full_dictionary,
        )

        server.handle_coa_packet(protocol, request, ("127.0.0.1", 12345))

        reply = protocol.send_response.call_args.args[0]
        assert reply.code == PacketType.CoANAK
        assert int.from_bytes(reply[101][0], "big") == ErrorCause.UnsupportedExtension

    def test_default_disconnect_handler_sends_nak(self, full_dictionary):
        server = AuthAcctOnlyServer()
        protocol = MagicMock()
        request = packet.CoAPacket(
            code=PacketType.DisconnectRequest,
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=full_dictionary,
        )

        server.handle_disconnect_packet(protocol, request, ("127.0.0.1", 12345))

        reply = protocol.send_response.call_args.args[0]
        assert reply.code == PacketType.DisconnectNAK
        assert int.from_bytes(reply[101][0], "big") == ErrorCause.UnsupportedExtension
