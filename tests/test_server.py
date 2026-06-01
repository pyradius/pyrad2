import select
import socket
import unittest
import os
from .base import TEST_ROOT_PATH
from .mock import MockFinished
from .mock import MockFd
from .mock import MockPoll
from .mock import MockSocket
from .mock import MockClassMethod
from .mock import UnmockClassMethods
from pyrad2 import packet
from pyrad2.dictionary import Dictionary
from pyrad2.packet import PacketError
from pyrad2.server import RemoteHost
from pyrad2.server import Server
from pyrad2.server import ServerPacketError
from pyrad2.constants import PacketType


class TrivialObject:
    """dummy objec"""

    pass


class RemoteHostTests(unittest.TestCase):
    def testSimpleConstruction(self):
        host = RemoteHost(
            "address", "secret", "name", "authport", "acctport", "coaport"
        )
        self.assertEqual(host.address, "address")
        self.assertEqual(host.secret, "secret")
        self.assertEqual(host.name, "name")
        self.assertEqual(host.authport, "authport")
        self.assertEqual(host.acctport, "acctport")
        self.assertEqual(host.coaport, "coaport")

    def testNamedConstruction(self):
        host = RemoteHost(
            address="address",
            secret="secret",
            name="name",
            authport="authport",
            acctport="acctport",
            coaport="coaport",
        )
        self.assertEqual(host.address, "address")
        self.assertEqual(host.secret, "secret")
        self.assertEqual(host.name, "name")
        self.assertEqual(host.authport, "authport")
        self.assertEqual(host.acctport, "acctport")
        self.assertEqual(host.coaport, "coaport")


class ServerConstructiontests(unittest.TestCase):
    def testSimpleConstruction(self):
        server = Server()
        self.assertEqual(server.authfds, [])
        self.assertEqual(server.acctfds, [])
        self.assertEqual(server.authport, 1812)
        self.assertEqual(server.acctport, 1813)
        self.assertEqual(server.coaport, 3799)
        self.assertEqual(server.hosts, {})

    def testParameterOrder(self):
        server = Server([], "authport", "acctport", "coaport", "hosts", "dict")
        self.assertEqual(server.authfds, [])
        self.assertEqual(server.acctfds, [])
        self.assertEqual(server.authport, "authport")
        self.assertEqual(server.acctport, "acctport")
        self.assertEqual(server.coaport, "coaport")
        self.assertEqual(server.dict, "dict")

    def testBindDuringConstruction(self):
        def bind_to_address(self, addr):
            self.bound.append(addr)

        bta = Server.bind_to_address
        Server.bind_to_address = bind_to_address

        Server.bound = []
        server = Server(["one", "two", "three"])
        self.assertEqual(server.bound, ["one", "two", "three"])
        del Server.bound

        Server.bind_to_address = bta


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.orgsocket = socket.socket
        socket.socket = MockSocket
        self.server = Server()

    def tearDown(self):
        socket.socket = self.orgsocket

    def testBind(self):
        self.server.bind_to_address("192.168.13.13")
        self.assertEqual(len(self.server.authfds), 1)
        self.assertEqual(self.server.authfds[0].address, ("192.168.13.13", 1812))

        self.assertEqual(len(self.server.acctfds), 1)
        self.assertEqual(self.server.acctfds[0].address, ("192.168.13.13", 1813))

    def testBindv6(self):
        self.server.bind_to_address("2001:db8:123::1")
        self.assertEqual(len(self.server.authfds), 1)
        self.assertEqual(self.server.authfds[0].address, ("2001:db8:123::1", 1812))

        self.assertEqual(len(self.server.acctfds), 1)
        self.assertEqual(self.server.acctfds[0].address, ("2001:db8:123::1", 1813))

    def testgrab_packet(self):
        from pyrad2 import packet as packet_mod

        captured: dict[str, object] = {}

        def fake_parse(data, secret, dictionary):
            captured["data"] = data
            captured["secret"] = secret
            captured["dict"] = dictionary
            res = TrivialObject()
            res.data = data
            return res

        host = TrivialObject()
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

        self.assertTrue(isinstance(pkt, TrivialObject))
        self.assertTrue(pkt.fd is fd)
        self.assertEqual(pkt.source, ("10.0.0.1", 4242))
        self.assertEqual(captured["secret"], b"sharedsecret")
        self.assertEqual(captured["data"], b"raw-bytes")

    def testgrab_packet_unknown_host_raises(self):
        fd = MockFd()
        fd.source = ("stranger", 1812)
        with self.assertRaisesRegex(ServerPacketError, "unknown host"):
            self.server._grab_packet(fd)

    def testPrepareSocketNoFds(self):
        self.server._poll = MockPoll()
        self.server._prepare_sockets()

        self.assertEqual(self.server._poll.registry, {})
        self.assertEqual(self.server._realauthfds, [])
        self.assertEqual(self.server._realacctfds, [])

    def testPrepareSocketAuthFds(self):
        self.server._poll = MockPoll()
        self.server._fdmap = {}
        self.server.authfds = [MockFd(12), MockFd(14)]
        self.server._prepare_sockets()

        self.assertEqual(list(self.server._fdmap.keys()), [12, 14])
        self.assertEqual(
            self.server._poll.registry,
            {
                12: select.POLLIN | select.POLLPRI | select.POLLERR,
                14: select.POLLIN | select.POLLPRI | select.POLLERR,
            },
        )

    def testPrepareSocketAcctFds(self):
        self.server._poll = MockPoll()
        self.server._fdmap = {}
        self.server.acctfds = [MockFd(12), MockFd(14)]
        self.server._prepare_sockets()

        self.assertEqual(list(self.server._fdmap.keys()), [12, 14])
        self.assertEqual(
            self.server._poll.registry,
            {
                12: select.POLLIN | select.POLLPRI | select.POLLERR,
                14: select.POLLIN | select.POLLPRI | select.POLLERR,
            },
        )


class AuthPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.server.hosts["host"] = TrivialObject()
        self.server.hosts["host"].secret = "supersecret"
        self.packet = TrivialObject()
        self.packet.code = PacketType.AccessRequest
        self.packet.source = ("host", "port")

    def testHandleAuthPacketUnknownHost(self):
        self.packet.source = ("stranger", "port")
        try:
            self.server._handle_auth_packet(self.packet)
        except ServerPacketError as e:
            self.assertTrue("unknown host" in str(e))
        else:
            self.fail()

    def testHandleAuthPacketWrongPort(self):
        self.packet.code = PacketType.AccountingRequest
        try:
            self.server._handle_auth_packet(self.packet)
        except ServerPacketError as e:
            self.assertTrue("port" in str(e))
        else:
            self.fail()

    def testHandleAuthPacket(self):
        def handle_auth_packet(self, pkt):
            self.handled = pkt

        hap = Server.handle_auth_packet
        Server.handle_auth_packet = handle_auth_packet

        self.server._handle_auth_packet(self.packet)
        self.assertTrue(self.server.handled is self.packet)

        Server.handle_auth_packet = hap


class MessageAuthenticatorPolicyTests(unittest.TestCase):
    def setUp(self):
        self.dictionary = Dictionary(os.path.join(TEST_ROOT_PATH, "data/full"))
        self.remote_host = RemoteHost("host", b"secret", "host")

    def _server(self, **kwargs):
        return Server(hosts={"host": self.remote_host}, dict=self.dictionary, **kwargs)

    def _parse_auth_packet(self, pkt):
        parsed = packet.AuthPacket(
            packet=pkt.request_packet(),
            secret=b"secret",
            dict=self.dictionary,
        )
        parsed.source = ("host", 12345)
        return parsed

    def _parse_auth_packet_bytes(self, data):
        parsed = packet.AuthPacket(packet=data, secret=b"secret", dict=self.dictionary)
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
        with self.assertRaisesRegex(PacketError, "EAP-Message requires"):
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

        with self.assertRaisesRegex(PacketError, "Message-Authenticator is invalid"):
            self._server()._handle_auth_packet(self._parse_auth_packet_bytes(bytes(data)))

    def test_require_message_authenticator_rejects_plain_auth_request(self):
        pkt = self._auth_packet()

        with self.assertRaisesRegex(PacketError, "attribute is required"):
            self._server(require_message_authenticator=True)._handle_auth_packet(
                self._parse_auth_packet(pkt)
            )

    def test_blastradius_default_rejects_plain_auth_request(self):
        # C2 regression: the constructor default now mitigates BlastRADIUS
        # (CVE-2024-3596). A plain Access-Request without Message-Authenticator
        # MUST be rejected without the caller having to opt in.
        pkt = self._auth_packet()

        with self.assertRaisesRegex(PacketError, "attribute is required"):
            self._server()._handle_auth_packet(self._parse_auth_packet(pkt))

    def test_create_reply_packet_preserves_request_message_authenticator_policy(self):
        server = self._server()
        pkt = self._auth_packet()
        pkt.add_message_authenticator()
        parsed = self._parse_auth_packet(pkt)

        reply = server.create_reply_packet(parsed)

        self.assertTrue(reply.has_message_authenticator())

    def test_auth_status_server_replies_without_auth_side_effects(self):
        class CaptureFd:
            def __init__(self):
                self.sent = []

            def sendto(self, data, target):
                self.sent.append((data, target))

        server = self._server()
        server.handle_auth_packet = lambda pkt: self.fail("auth handler called")
        parsed = self._parse_status_packet(self._status_packet())
        parsed.fd = CaptureFd()

        server._handle_auth_packet(parsed)

        self.assertEqual(len(parsed.fd.sent), 1)
        rawreply, target = parsed.fd.sent[0]
        reply = parsed.create_reply(packet=rawreply)
        self.assertEqual(target, parsed.source)
        self.assertEqual(reply.code, PacketType.AccessAccept)
        self.assertTrue(parsed.verify_reply(reply, rawreply=rawreply))

    def test_accounting_status_server_replies_without_accounting_side_effects(self):
        class CaptureFd:
            def __init__(self):
                self.sent = []

            def sendto(self, data, target):
                self.sent.append((data, target))

        server = self._server()
        server.handle_acct_packet = lambda pkt: self.fail("acct handler called")
        parsed = self._parse_status_packet(self._status_packet())
        parsed.fd = CaptureFd()

        server._handle_acct_packet(parsed)

        rawreply, _target = parsed.fd.sent[0]
        reply = parsed.create_reply(packet=rawreply)
        self.assertEqual(reply.code, PacketType.AccountingResponse)
        self.assertTrue(parsed.verify_reply(reply, rawreply=rawreply))


class AcctPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.server.hosts["host"] = TrivialObject()
        self.server.hosts["host"].secret = "supersecret"
        self.packet = TrivialObject()
        self.packet.code = PacketType.AccountingRequest
        self.packet.source = ("host", "port")

    def testHandleAcctPacketUnknownHost(self):
        self.packet.source = ("stranger", "port")
        try:
            self.server._handle_acct_packet(self.packet)
        except ServerPacketError as e:
            self.assertTrue("unknown host" in str(e))
        else:
            self.fail()

    def testHandleAcctPacketWrongPort(self):
        self.packet.code = PacketType.AccessRequest
        try:
            self.server._handle_acct_packet(self.packet)
        except ServerPacketError as e:
            self.assertTrue("port" in str(e))
        else:
            self.fail()

    def testHandleAcctPacket(self):
        def handle_acct_packet(self, pkt):
            self.handled = pkt

        hap = Server.handle_acct_packet
        Server.handle_acct_packet = handle_acct_packet

        self.server._handle_acct_packet(self.packet)
        self.assertTrue(self.server.handled is self.packet)

        Server.handle_acct_packet = hap


class OtherTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()

    def tearDown(self):
        UnmockClassMethods(Server)

    def testcreate_reply_packet(self):
        class TrivialPacket:
            source = object()

            def create_reply(self, **kw):
                reply = TrivialObject()
                reply.kw = kw
                return reply

        reply = self.server.create_reply_packet(TrivialPacket(), one="one", two="two")
        self.assertTrue(isinstance(reply, TrivialObject))
        self.assertTrue(reply.source is TrivialPacket.source)
        self.assertEqual(reply.kw, dict(one="one", two="two"))

    def testAuthProcessInput(self):
        fd = MockFd(1)
        self.server._realauthfds = [1]
        MockClassMethod(Server, "_grab_packet")
        MockClassMethod(Server, "_handle_auth_packet")

        self.server._process_input(fd)
        self.assertEqual(
            [x[0] for x in self.server.called], ["_grab_packet", "_handle_auth_packet"]
        )
        self.assertEqual(self.server.called[0][1][0], fd)

    def testAcctProcessInput(self):
        fd = MockFd(1)
        self.server._realauthfds = []
        self.server._realacctfds = [1]
        MockClassMethod(Server, "_grab_packet")
        MockClassMethod(Server, "_handle_acct_packet")

        self.server._process_input(fd)
        self.assertEqual(
            [x[0] for x in self.server.called], ["_grab_packet", "_handle_acct_packet"]
        )
        self.assertEqual(self.server.called[0][1][0], fd)


class ServerRunTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.origpoll = select.poll
        select.poll = MockPoll

    def tearDown(self):
        MockPoll.results = []
        select.poll = self.origpoll
        UnmockClassMethods(Server)

    def testRunInitializes(self):
        MockClassMethod(Server, "_prepare_sockets")
        self.assertRaises(MockFinished, self.server.run)
        self.assertEqual(self.server.called, [("_prepare_sockets", (), {})])
        self.assertTrue(isinstance(self.server._fdmap, dict))
        self.assertTrue(isinstance(self.server._poll, MockPoll))

    def testRunIgnoresPollErrors(self):
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLERR)]
        self.assertRaises(MockFinished, self.server.run)

    def testRunIgnoresServerPacketErrors(self):
        def RaisePacketError(self, fd):
            raise ServerPacketError

        MockClassMethod(Server, "_process_input", RaisePacketError)
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        self.assertRaises(MockFinished, self.server.run)

    def testRunIgnoresPacketErrors(self):
        def RaisePacketError(self, fd):
            raise PacketError

        MockClassMethod(Server, "_process_input", RaisePacketError)
        self.server.authfds = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        self.assertRaises(MockFinished, self.server.run)

    def testRunRunsProcessInput(self):
        MockClassMethod(Server, "_process_input")
        self.server.authfds = fd = [MockFd()]
        MockPoll.results = [(0, select.POLLIN)]
        self.assertRaises(MockFinished, self.server.run)
        self.assertEqual(self.server.called, [("_process_input", (fd[0],), {})])


if not hasattr(select, "poll"):
    del SocketTests
    del ServerRunTests
