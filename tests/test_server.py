import select
import socket

import pytest

from pyrad2 import packet
from pyrad2.constants import PacketType
from pyrad2.packet import PacketError
from pyrad2.server import RemoteHost, Server, ServerPacketError

from .mock import (
    MockClassMethod,
    MockFd,
    MockFinished,
    MockPoll,
    MockSocket,
    UnmockClassMethods,
)


class _TrivialObject:
    """dummy object"""


class TestRemoteHost:
    def test_simple_construction(self):
        host = RemoteHost(
            "address", "secret", "name", "authport", "acctport", "coaport"
        )
        assert host.address == "address"
        assert host.secret == "secret"
        assert host.name == "name"
        assert host.authport == "authport"
        assert host.acctport == "acctport"
        assert host.coaport == "coaport"

    def test_named_construction(self):
        host = RemoteHost(
            address="address",
            secret="secret",
            name="name",
            authport="authport",
            acctport="acctport",
            coaport="coaport",
        )
        assert host.address == "address"
        assert host.secret == "secret"
        assert host.name == "name"
        assert host.authport == "authport"
        assert host.acctport == "acctport"
        assert host.coaport == "coaport"


class TestServerConstruction:
    def test_simple_construction(self):
        server = Server()
        assert server.authfds == []
        assert server.acctfds == []
        assert server.authport == 1812
        assert server.acctport == 1813
        assert server.coaport == 3799
        assert server.hosts == {}

    def test_parameter_order(self):
        server = Server([], "authport", "acctport", "coaport", "hosts", "dict")
        assert server.authfds == []
        assert server.acctfds == []
        assert server.authport == "authport"
        assert server.acctport == "acctport"
        assert server.coaport == "coaport"
        assert server.dict == "dict"

    def test_bind_during_construction(self):
        def bind_to_address(self, addr):
            self.bound.append(addr)

        bta = Server.bind_to_address
        Server.bind_to_address = bind_to_address

        Server.bound = []
        try:
            server = Server(["one", "two", "three"])
            assert server.bound == ["one", "two", "three"]
        finally:
            del Server.bound
            Server.bind_to_address = bta


@pytest.mark.skipif(not hasattr(select, "poll"), reason="select.poll not available")
class TestSocket:
    def setup_method(self):
        self._orgsocket = socket.socket
        socket.socket = MockSocket
        self.server = Server()

    def teardown_method(self):
        socket.socket = self._orgsocket

    def test_bind(self):
        self.server.bind_to_address("192.168.13.13")
        assert len(self.server.authfds) == 1
        assert self.server.authfds[0].address == ("192.168.13.13", 1812)

        assert len(self.server.acctfds) == 1
        assert self.server.acctfds[0].address == ("192.168.13.13", 1813)

    def test_bind_v6(self):
        self.server.bind_to_address("2001:db8:123::1")
        assert len(self.server.authfds) == 1
        assert self.server.authfds[0].address == ("2001:db8:123::1", 1812)

        assert len(self.server.acctfds) == 1
        assert self.server.acctfds[0].address == ("2001:db8:123::1", 1813)

    def test_grab_packet(self):
        from pyrad2 import packet as packet_mod

        captured: dict[str, object] = {}

        def fake_parse(data, secret, dictionary):
            captured["data"] = data
            captured["secret"] = secret
            captured["dict"] = dictionary
            res = _TrivialObject()
            res.data = data
            return res

        host = _TrivialObject()
        host.secret = b"sharedsecret"
        self.server.hosts["10.0.0.1"] = host

        fd = MockFd()
        fd.source = ("10.0.0.1", 4242)
        fd.data = b"raw-bytes"

        orig_parse = packet_mod.parse_packet
        packet_mod.parse_packet = fake_parse
        try:
            pkt = self.server._grab_packet(fd)
        finally:
            packet_mod.parse_packet = orig_parse

        assert isinstance(pkt, _TrivialObject)
        assert pkt.fd is fd
        assert pkt.source == ("10.0.0.1", 4242)
        assert captured["secret"] == b"sharedsecret"
        assert captured["data"] == b"raw-bytes"

    def test_grab_packet_unknown_host_raises(self):
        fd = MockFd()
        fd.source = ("stranger", 1812)
        with pytest.raises(ServerPacketError, match="unknown host"):
            self.server._grab_packet(fd)

    def test_prepare_socket_no_fds(self):
        self.server._poll = MockPoll()
        self.server._prepare_sockets()

        assert self.server._poll.registry == {}
        assert self.server._realauthfds == set()
        assert self.server._realacctfds == set()

    def test_prepare_socket_auth_fds(self):
        self.server._poll = MockPoll()
        self.server._fdmap = {}
        self.server.authfds = [MockFd(12), MockFd(14)]
        self.server._prepare_sockets()

        assert list(self.server._fdmap.keys()) == [12, 14]
        assert self.server._poll.registry == {
            12: select.POLLIN | select.POLLPRI | select.POLLERR,
            14: select.POLLIN | select.POLLPRI | select.POLLERR,
        }

    def test_prepare_socket_acct_fds(self):
        self.server._poll = MockPoll()
        self.server._fdmap = {}
        self.server.acctfds = [MockFd(12), MockFd(14)]
        self.server._prepare_sockets()

        assert list(self.server._fdmap.keys()) == [12, 14]
        assert self.server._poll.registry == {
            12: select.POLLIN | select.POLLPRI | select.POLLERR,
            14: select.POLLIN | select.POLLPRI | select.POLLERR,
        }


class TestAuthPacketHandling:
    def setup_method(self):
        self.server = Server()
        self.server.hosts["host"] = _TrivialObject()
        self.server.hosts["host"].secret = "supersecret"
        self.packet = _TrivialObject()
        self.packet.code = PacketType.AccessRequest
        self.packet.source = ("host", "port")

    def test_handle_auth_packet_unknown_host(self):
        self.packet.source = ("stranger", "port")
        with pytest.raises(ServerPacketError, match="unknown host"):
            self.server._handle_auth_packet(self.packet)

    def test_handle_auth_packet_wrong_port(self):
        self.packet.code = PacketType.AccountingRequest
        with pytest.raises(ServerPacketError, match="port"):
            self.server._handle_auth_packet(self.packet)

    def test_handle_auth_packet(self):
        def handle_auth_packet(self, pkt):
            self.handled = pkt

        hap = Server.handle_auth_packet
        Server.handle_auth_packet = handle_auth_packet

        try:
            self.server._handle_auth_packet(self.packet)
            assert self.server.handled is self.packet
        finally:
            Server.handle_auth_packet = hap


class TestMessageAuthenticatorPolicy:
    @pytest.fixture(autouse=True)
    def _setup(self, full_dictionary):
        self.dictionary = full_dictionary
        self.remote_host = RemoteHost("host", b"secret", "host")

    def _server(self, **kwargs):
        return Server(
            hosts={"host": self.remote_host}, dict=self.dictionary, **kwargs
        )

    def _parse_auth_packet(self, pkt):
        parsed = packet.AuthPacket(
            packet=pkt.request_packet(),
            secret=b"secret",
            dict=self.dictionary,
        )
        parsed.source = ("host", 12345)
        return parsed

    def _parse_auth_packet_bytes(self, data):
        parsed = packet.AuthPacket(
            packet=data, secret=b"secret", dict=self.dictionary
        )
        parsed.source = ("host", 12345)
        return parsed

    def _auth_packet(self, **attributes):
        return packet.AuthPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=self.dictionary,
            **attributes,
        )

    def _status_packet(self):
        return packet.StatusPacket(
            id=1,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
            dict=self.dictionary,
        )

    def _parse_status_packet(self, pkt):
        parsed = packet.StatusPacket(
            packet=pkt.request_packet(),
            secret=b"secret",
            dict=self.dictionary,
        )
        parsed.source = ("host", 12345)
        return parsed

    def test_eap_message_requires_message_authenticator(self):
        pkt = self._auth_packet()
        pkt[79] = [b"\x02\x01\x00\x05\x01"]

        # require_message_authenticator=False isolates the EAP-specific
        # policy gate (otherwise the general BlastRADIUS rule fires first).
        with pytest.raises(PacketError, match="EAP-Message requires"):
            self._server(
                require_message_authenticator=False
            )._handle_auth_packet(self._parse_auth_packet(pkt))

    def test_valid_message_authenticator_is_accepted(self):
        server = self._server()
        pkt = self._auth_packet()
        pkt[79] = [b"\x02\x01\x00\x05\x01"]
        pkt.add_message_authenticator()
        parsed = self._parse_auth_packet(pkt)

        server._handle_auth_packet(parsed)

    def test_invalid_message_authenticator_is_rejected(self):
        pkt = self._auth_packet()
        pkt.add_message_authenticator()
        data = bytearray(pkt.request_packet())
        data[-1] ^= 0xFF

        with pytest.raises(PacketError, match="Message-Authenticator is invalid"):
            self._server()._handle_auth_packet(
                self._parse_auth_packet_bytes(bytes(data))
            )

    def test_require_message_authenticator_rejects_plain_auth_request(self):
        pkt = self._auth_packet()

        with pytest.raises(PacketError, match="attribute is required"):
            self._server(
                require_message_authenticator=True
            )._handle_auth_packet(self._parse_auth_packet(pkt))

    def test_blastradius_default_rejects_plain_auth_request(self):
        # C2 regression: the constructor default now mitigates BlastRADIUS
        # (CVE-2024-3596). A plain Access-Request without Message-Authenticator
        # MUST be rejected without the caller having to opt in.
        pkt = self._auth_packet()

        with pytest.raises(PacketError, match="attribute is required"):
            self._server()._handle_auth_packet(self._parse_auth_packet(pkt))

    def test_create_reply_packet_preserves_request_message_authenticator_policy(self):
        server = self._server()
        pkt = self._auth_packet()
        pkt.add_message_authenticator()
        parsed = self._parse_auth_packet(pkt)

        reply = server.create_reply_packet(parsed)

        assert reply.has_message_authenticator()

    def test_auth_status_server_replies_without_auth_side_effects(self):
        class CaptureFd:
            def __init__(self):
                self.sent = []

            def sendto(self, data, target):
                self.sent.append((data, target))

        server = self._server()
        server.handle_auth_packet = lambda pkt: pytest.fail("auth handler called")
        parsed = self._parse_status_packet(self._status_packet())
        parsed.fd = CaptureFd()

        server._handle_auth_packet(parsed)

        assert len(parsed.fd.sent) == 1
        rawreply, target = parsed.fd.sent[0]
        reply = parsed.create_reply(packet=rawreply)
        assert target == parsed.source
        assert reply.code == PacketType.AccessAccept
        assert parsed.verify_reply(reply, rawreply=rawreply)

    def test_accounting_status_server_replies_without_accounting_side_effects(self):
        class CaptureFd:
            def __init__(self):
                self.sent = []

            def sendto(self, data, target):
                self.sent.append((data, target))

        server = self._server()
        server.handle_acct_packet = lambda pkt: pytest.fail("acct handler called")
        parsed = self._parse_status_packet(self._status_packet())
        parsed.fd = CaptureFd()

        server._handle_acct_packet(parsed)

        rawreply, _target = parsed.fd.sent[0]
        reply = parsed.create_reply(packet=rawreply)
        assert reply.code == PacketType.AccountingResponse
        assert parsed.verify_reply(reply, rawreply=rawreply)


class TestAcctPacketHandling:
    def setup_method(self):
        self.server = Server()
        self.server.hosts["host"] = _TrivialObject()
        self.server.hosts["host"].secret = "supersecret"
        self.packet = _TrivialObject()
        self.packet.code = PacketType.AccountingRequest
        self.packet.source = ("host", "port")

    def test_handle_acct_packet_unknown_host(self):
        self.packet.source = ("stranger", "port")
        with pytest.raises(ServerPacketError, match="unknown host"):
            self.server._handle_acct_packet(self.packet)

    def test_handle_acct_packet_wrong_port(self):
        self.packet.code = PacketType.AccessRequest
        with pytest.raises(ServerPacketError, match="port"):
            self.server._handle_acct_packet(self.packet)

    def test_handle_acct_packet(self):
        def handle_acct_packet(self, pkt):
            self.handled = pkt

        hap = Server.handle_acct_packet
        Server.handle_acct_packet = handle_acct_packet

        try:
            self.server._handle_acct_packet(self.packet)
            assert self.server.handled is self.packet
        finally:
            Server.handle_acct_packet = hap


class TestOther:
    def setup_method(self):
        self.server = Server()

    def teardown_method(self):
        UnmockClassMethods(Server)

    def test_create_reply_packet(self):
        class TrivialPacket:
            source = object()

            def create_reply(self, **kw):
                reply = _TrivialObject()
                reply.kw = kw
                return reply

        reply = self.server.create_reply_packet(
            TrivialPacket(), one="one", two="two"
        )
        assert isinstance(reply, _TrivialObject)
        assert reply.source is TrivialPacket.source
        assert reply.kw == dict(one="one", two="two")

    def test_auth_process_input(self):
        fd = MockFd(1)
        self.server._realauthfds = [1]
        MockClassMethod(Server, "_grab_packet")
        MockClassMethod(Server, "_handle_auth_packet")

        self.server._process_input(fd)
        assert [x[0] for x in self.server.called] == [
            "_grab_packet",
            "_handle_auth_packet",
        ]
        assert self.server.called[0][1][0] == fd

    def test_acct_process_input(self):
        fd = MockFd(1)
        self.server._realauthfds = []
        self.server._realacctfds = [1]
        MockClassMethod(Server, "_grab_packet")
        MockClassMethod(Server, "_handle_acct_packet")

        self.server._process_input(fd)
        assert [x[0] for x in self.server.called] == [
            "_grab_packet",
            "_handle_acct_packet",
        ]
        assert self.server.called[0][1][0] == fd


@pytest.mark.skipif(not hasattr(select, "poll"), reason="select.poll not available")
class TestServerRun:
    def setup_method(self):
        self.server = Server()
        self.origpoll = select.poll
        select.poll = MockPoll

    def teardown_method(self):
        MockPoll.results = []
        select.poll = self.origpoll
        UnmockClassMethods(Server)

    def test_run_initializes(self):
        MockClassMethod(Server, "_prepare_sockets")
        with pytest.raises(MockFinished):
            self.server.run()
        assert self.server.called == [("_prepare_sockets", (), {})]
        assert isinstance(self.server._fdmap, dict)
        assert isinstance(self.server._poll, MockPoll)

    def test_run_ignores_poll_errors(self):
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLERR)]
        with pytest.raises(MockFinished):
            self.server.run()

    def test_run_ignores_server_packet_errors(self):
        def RaisePacketError(self, fd):
            raise ServerPacketError

        MockClassMethod(Server, "_process_input", RaisePacketError)
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        with pytest.raises(MockFinished):
            self.server.run()

    def test_run_ignores_packet_errors(self):
        def RaisePacketError(self, fd):
            raise PacketError

        MockClassMethod(Server, "_process_input", RaisePacketError)
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        with pytest.raises(MockFinished):
            self.server.run()

    def test_run_runs_process_input(self):
        MockClassMethod(Server, "_process_input")
        self.server.authfds = fd = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        with pytest.raises(MockFinished):
            self.server.run()
        assert self.server.called == [("_process_input", (fd[0],), {})]
