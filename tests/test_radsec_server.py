import asyncio
import os
import ssl
import struct
import unittest

from pyrad2.constants import ErrorCause, PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import PacketError
from pyrad2.radsec.client import RadSecClient
from pyrad2.radsec.server import RadSecServer as BaseRadSecServer
from pyrad2.radsec.server import UnknownHost
from pyrad2.server import RemoteHost
from pyrad2.tools import get_cert_fingerprint

from .base import TEST_ROOT_PATH

TEST_HOST = RemoteHost(
    "name",
    b"radsec",
    "127.0.0.1",
)

SERVER_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/server/server.cert.pem")
SERVER_KEYFILE = os.path.join(TEST_ROOT_PATH, "certs/server/server.key.pem")
CA_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/ca/ca.cert.pem")
CLIENT_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/client/client.cert.pem")
CLIENT_KEYFILE = os.path.join(TEST_ROOT_PATH, "certs/client/client.key.pem")
EXAMPLE_ROOT_PATH = os.path.join(os.path.dirname(TEST_ROOT_PATH), "examples")
EXAMPLE_SERVER_CERTFILE = os.path.join(
    EXAMPLE_ROOT_PATH, "certs/server/server.cert.pem"
)


def load_der_cert(path):
    with open(path) as cert_file:
        return ssl.PEM_cert_to_DER_cert(cert_file.read())


def load_cert_fingerprint(path):
    return get_cert_fingerprint(load_der_cert(path))


class FakeSSLObject:
    def __init__(self, cert):
        self.cert = cert

    def getpeercert(self, binary_form=False):
        if binary_form:
            return self.cert
        return {"subject": "test"}


class FakeWriter:
    def __init__(self, cert):
        self.ssl_object = FakeSSLObject(cert)

    def get_extra_info(self, name, default=None):
        if name == "ssl_object":
            return self.ssl_object
        return default


class FakeRadSecReader:
    def __init__(self, *packets, exception=None, delay=None):
        self.packets = list(packets)
        self.exception = exception
        self.delay = delay
        self.current = b""
        self.offset = 0

    async def readexactly(self, n):
        if self.delay is not None:
            await asyncio.sleep(self.delay)
        if self.exception is not None:
            raise self.exception
        if not self.current:
            if not self.packets:
                raise asyncio.IncompleteReadError(partial=b"", expected=n)
            self.current = self.packets.pop(0)
            self.offset = 0

        end = self.offset + n
        if end > len(self.current):
            raise asyncio.IncompleteReadError(
                partial=self.current[self.offset :], expected=n
            )

        chunk = self.current[self.offset : end]
        self.offset = end
        if self.offset == len(self.current):
            self.current = b""
            self.offset = 0
        return chunk


class FakeRadSecWriter:
    def __init__(self, cert=None, peername=("127.0.0.1", 2083)):
        self.cert = cert
        self.peername = peername
        self.writes = []
        self.closed = False

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def is_closing(self):
        return self.closed

    def get_extra_info(self, name, default=None):
        if name == "peername":
            return self.peername
        if name == "peercert" and self.cert is not None:
            return {"subject": "test"}
        if name == "ssl_object" and self.cert is not None:
            return FakeSSLObject(self.cert)
        return default


class FakeRadSecReply:
    def __init__(self, data):
        self.data = data


class FakeRadSecPacket:
    def __init__(self, id=1, verify=True):
        self.id = id
        self.verify = verify
        self.responses = []

    def request_packet(self):
        return f"request-{self.id}".encode()

    def create_reply(self, packet):
        self.responses.append(packet)
        return FakeRadSecReply(packet)

    def verify_reply(self, reply, response):
        return self.verify


def raw_radius_response(id=1):
    return struct.pack("!BBH16s", PacketType.AccessAccept, id, 20, b"\x00" * 16)


class RemoteHostTests(unittest.TestCase):
    def test_simple_construction(self):
        host = RemoteHost(
            "127.0.0.1",
            b"radsec",
            "name",
        )
        self.assertEqual(host.name, "name")
        self.assertEqual(host.address, "127.0.0.1")
        self.assertEqual(host.secret, b"radsec")


class ExampleCertificateTests(unittest.TestCase):
    def test_example_server_certificate_matches_local_development_hosts(self):
        cert = ssl._ssl._test_decode_cert(EXAMPLE_SERVER_CERTFILE)
        subject_alt_names = set(cert["subjectAltName"])

        self.assertIn(("DNS", "localhost"), subject_alt_names)
        self.assertIn(("DNS", "radsec-server"), subject_alt_names)
        self.assertIn(("IP Address", "127.0.0.1"), subject_alt_names)
        self.assertIn(("IP Address", "0:0:0:0:0:0:0:1"), subject_alt_names)


class RadSecServer(BaseRadSecServer):
    # Test subclass: legacy fixtures here build plain Access-Requests
    # without a Message-Authenticator AVP. Default the BlastRADIUS knob
    # off so unrelated tests keep working; the MA-policy tests still
    # set it back to True explicitly.
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("require_message_authenticator", False)
        super().__init__(*args, **kwargs)

    async def handle_access_request(self, packet):
        reply = packet.create_reply(
            **{
                "Service-Type": "Framed-User",
                "Framed-IP-Address": "192.168.0.1",
                "Framed-IPv6-Prefix": "fc66::1/64",
            },
        )

        reply.code = PacketType.AccessAccept
        return reply

    async def handle_accounting(self, packet):
        return packet.create_reply()

    async def handle_disconnect(self, packet):
        reply = packet.create_reply()
        reply.code = 45  # COA NAK
        return reply

    async def handle_coa(self, packet):
        return packet.create_reply()


class AuthAcctOnlyRadSecServer(BaseRadSecServer):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("require_message_authenticator", False)
        super().__init__(*args, **kwargs)

    async def handle_access_request(self, packet):
        reply = packet.create_reply()
        reply.code = PacketType.AccessAccept
        return reply

    async def handle_accounting(self, packet):
        return packet.create_reply()


class ServerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dictionary = Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary"))

        # require_message_authenticator=False / enforce_ma=False keep the
        # legacy test fixtures (which build plain Access-Requests without a
        # Message-Authenticator AVP) working under the BlastRADIUS-default
        # constructors. Tests that exercise the policy gate set it back to
        # True explicitly.
        self.server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            require_message_authenticator=False,
        )
        self.server.hosts = {"127.0.0.1": TEST_HOST}

        self.client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            dict=self.dictionary,
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
        )

    def test_simple_construction(self):
        self.assertEqual(self.server.listen_address, "0.0.0.0")
        self.assertEqual(self.server.listen_port, 2083)
        self.assertEqual(self.server.hosts, {"127.0.0.1": TEST_HOST})
        self.assertEqual(self.server.dict, self.dictionary)
        self.assertEqual(self.server.verify_packet, False)
        self.assertTrue(self.server.enable_coa)
        self.assertTrue(self.server.enable_disconnect)
        self.assertEqual(self.server.ssl_ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(
            self.server.ssl_ctx.minimum_version,
            BaseRadSecServer.DEFAULT_MINIMUM_TLS_VERSION,
        )

    def test_auth_acct_only_subclass_is_concrete(self):
        server = AuthAcctOnlyRadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
        )

        self.assertIsInstance(server, BaseRadSecServer)

    def test_client_uses_secure_tls_defaults(self):
        self.assertTrue(self.client.ssl_ctx.check_hostname)
        self.assertEqual(self.client.ssl_ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(
            self.client.ssl_ctx.minimum_version,
            RadSecClient.DEFAULT_MINIMUM_TLS_VERSION,
        )

    def test_client_can_disable_hostname_validation_explicitly(self):
        client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            dict=self.dictionary,
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
            check_hostname=False,
        )

        self.assertFalse(client.ssl_ctx.check_hostname)

    def test_server_fingerprint_allowlist_accepts_known_client_certificate(self):
        fingerprint = load_cert_fingerprint(CLIENT_CERTFILE)
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            allowed_client_fingerprints={fingerprint},
        )

        self.assertTrue(
            server._verify_client_fingerprint(load_der_cert(CLIENT_CERTFILE))
        )

    def test_server_fingerprint_allowlist_rejects_unknown_client_certificate(self):
        fingerprint = load_cert_fingerprint(SERVER_CERTFILE)
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            allowed_client_fingerprints={fingerprint},
        )

        self.assertFalse(
            server._verify_client_fingerprint(load_der_cert(CLIENT_CERTFILE))
        )
        self.assertFalse(server._verify_client_fingerprint(None))

    def test_client_fingerprint_allowlist_accepts_known_server_certificate(self):
        fingerprint = load_cert_fingerprint(SERVER_CERTFILE)
        client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            dict=self.dictionary,
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
            allowed_server_fingerprints={fingerprint},
        )

        self.assertTrue(
            client._verify_server_fingerprint(FakeWriter(load_der_cert(SERVER_CERTFILE)))
        )

    def test_client_fingerprint_allowlist_rejects_unknown_server_certificate(self):
        fingerprint = load_cert_fingerprint(CLIENT_CERTFILE)
        client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            dict=self.dictionary,
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
            allowed_server_fingerprints={fingerprint},
        )

        self.assertFalse(
            client._verify_server_fingerprint(FakeWriter(load_der_cert(SERVER_CERTFILE)))
        )

    async def test_unknown_host(self):
        with self.assertRaises(UnknownHost):
            await self.server.packet_received({}, "4.4.4.4")

    async def test_verify_packet_dispatches_auth_request_verifier(self):
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            verify_packet=True,
        )
        server.hosts = {"127.0.0.1": TEST_HOST}
        request = self.client.create_auth_packet(
            code=PacketType.AccessRequest, User_Name="wichert"
        )

        reply = await server.packet_received(request.request_packet(), "127.0.0.1")

        self.assertEqual(reply.code, PacketType.AccessAccept)

    async def test_verify_packet_dispatches_accounting_request_verifier(self):
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            verify_packet=True,
        )
        server.hosts = {"127.0.0.1": TEST_HOST}
        request = self.client.create_acct_packet(
            code=PacketType.AccountingRequest, User_Name="wichert"
        )

        reply = await server.packet_received(request.request_packet(), "127.0.0.1")

        self.assertEqual(reply.code, PacketType.AccountingResponse)

    async def test_verify_packet_rejects_invalid_accounting_authenticator(self):
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            verify_packet=True,
        )
        server.hosts = {"127.0.0.1": TEST_HOST}
        request = self.client.create_acct_packet(
            code=PacketType.AccountingRequest, User_Name="wichert"
        )
        data = bytearray(request.request_packet())
        data[-1] ^= 0xFF

        with self.assertRaises(PacketError):
            await server.packet_received(bytes(data), "127.0.0.1")

    async def test_message_authenticator_policy_rejects_eap_without_ma(self):
        request = self.client.create_auth_packet(
            code=PacketType.AccessRequest, User_Name="wichert"
        )
        request[79] = [b"\x02\x01\x00\x05\x01"]

        with self.assertRaisesRegex(PacketError, "EAP-Message requires"):
            await self.server.packet_received(request.request_packet(), "127.0.0.1")

    async def test_message_authenticator_policy_accepts_valid_ma(self):
        request = self.client.create_auth_packet(
            code=PacketType.AccessRequest, User_Name="wichert"
        )
        request[79] = [b"\x02\x01\x00\x05\x01"]
        request.add_message_authenticator()

        reply = await self.server.packet_received(request.request_packet(), "127.0.0.1")

        self.assertEqual(reply.code, PacketType.AccessAccept)
        self.assertTrue(reply.has_message_authenticator())

    async def test_status_server_replies_without_handler_side_effects(self):
        async def fail_access_handler(packet):
            self.fail("access handler called")

        self.server.handle_access_request = fail_access_handler
        request = self.client.create_status_packet()

        reply = await self.server.packet_received(request.request_packet(), "127.0.0.1")

        self.assertEqual(reply.code, PacketType.AccessAccept)
        self.assertTrue(reply.has_message_authenticator())

    async def test_status_server_requires_message_authenticator(self):
        request = self.client.create_status_packet()
        request.authenticator = b"0123456789ABCDEF"
        raw = struct.pack(
            "!BBH16s",
            PacketType.StatusServer,
            request.id,
            20,
            request.authenticator,
        )

        with self.assertRaisesRegex(PacketError, "Status-Server requires"):
            await self.server.packet_received(raw, "127.0.0.1")

    async def test_handle_client_reads_multiple_packets_from_one_stream(self):
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
        )
        server.hosts = {"127.0.0.1": TEST_HOST}
        request1 = self.client.create_auth_packet(
            code=PacketType.AccessRequest, User_Name="one"
        )
        request2 = self.client.create_auth_packet(
            code=PacketType.AccessRequest, User_Name="two"
        )
        reader = FakeRadSecReader(request1.request_packet(), request2.request_packet())
        writer = FakeRadSecWriter(peername=("127.0.0.1", 44000))

        await server._handle_client(reader, writer)

        self.assertEqual(len(writer.writes), 2)
        self.assertTrue(writer.closed)

    async def test_handle_client_closes_after_max_packets(self):
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            max_packets_per_connection=1,
        )
        server.hosts = {"127.0.0.1": TEST_HOST}
        request1 = self.client.create_auth_packet(
            code=PacketType.AccessRequest, User_Name="one"
        )
        request2 = self.client.create_auth_packet(
            code=PacketType.AccessRequest, User_Name="two"
        )
        reader = FakeRadSecReader(request1.request_packet(), request2.request_packet())
        writer = FakeRadSecWriter(peername=("127.0.0.1", 44001))

        await server._handle_client(reader, writer)

        # The limit must close the connection after the first packet — the
        # second request is never serviced even though the reader has it
        # queued.
        self.assertEqual(len(writer.writes), 1)
        self.assertTrue(writer.closed)

    async def test_handle_client_closes_on_read_timeout(self):
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            connection_read_timeout=0.01,
        )
        server.hosts = {"127.0.0.1": TEST_HOST}
        # Reader sleeps longer than the timeout, so the read must abort.
        reader = FakeRadSecReader(delay=0.2)
        writer = FakeRadSecWriter(peername=("127.0.0.1", 44002))

        await server._handle_client(reader, writer)

        self.assertEqual(writer.writes, [])
        self.assertTrue(writer.closed)

    async def test_default_coa_handler_returns_nak(self):
        server = AuthAcctOnlyRadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
        )
        server.hosts = {"127.0.0.1": TEST_HOST}
        request = self.client.create_coa_packet(code=PacketType.CoARequest)

        reply = await server.packet_received(request.request_packet(), "127.0.0.1")

        self.assertEqual(reply.code, PacketType.CoANAK)
        self.assertEqual(
            int.from_bytes(reply[101][0], "big"), ErrorCause.UnsupportedExtension
        )

    async def test_default_disconnect_handler_returns_nak(self):
        server = AuthAcctOnlyRadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
        )
        server.hosts = {"127.0.0.1": TEST_HOST}
        request = self.client.create_coa_packet(code=PacketType.DisconnectRequest)

        reply = await server.packet_received(request.request_packet(), "127.0.0.1")

        self.assertEqual(reply.code, PacketType.DisconnectNAK)
        self.assertEqual(
            int.from_bytes(reply[101][0], "big"), ErrorCause.UnsupportedExtension
        )

    async def test_disabled_coa_returns_nak_without_handler(self):
        self.server.enable_coa = False
        request = self.client.create_coa_packet(code=PacketType.CoARequest)

        reply = await self.server.packet_received(request.request_packet(), "127.0.0.1")

        self.assertEqual(reply.code, PacketType.CoANAK)


class RadSecClientConnectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = RadSecClient(
            server="127.0.0.1",
            secret=b"radsec",
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
            check_hostname=False,
            timeout=0.01,
            reconnect_backoff=0,
        )

    async def asyncTearDown(self):
        await self.client.close()

    async def test_send_packet_reuses_connection_by_default(self):
        reader = FakeRadSecReader(raw_radius_response(1), raw_radius_response(2))
        writer = FakeRadSecWriter()
        connections = []

        async def open_connection():
            connections.append(writer)
            return reader, writer

        self.client._open_connection = open_connection

        reply1 = await self.client._send_packet(FakeRadSecPacket(id=1))
        reply2 = await self.client._send_packet(FakeRadSecPacket(id=2))

        self.assertIsNotNone(reply1)
        self.assertIsNotNone(reply2)
        self.assertEqual(len(connections), 1)
        self.assertEqual(writer.writes, [b"request-1", b"request-2"])
        self.assertFalse(writer.closed)

    async def test_send_packet_can_disable_connection_reuse(self):
        self.client.reuse_connection = False
        connections = []

        async def open_connection():
            writer = FakeRadSecWriter()
            connections.append(writer)
            return FakeRadSecReader(raw_radius_response(len(connections))), writer

        self.client._open_connection = open_connection

        await self.client._send_packet(FakeRadSecPacket(id=1))
        await self.client._send_packet(FakeRadSecPacket(id=2))

        self.assertEqual(len(connections), 2)
        self.assertTrue(all(writer.closed for writer in connections))

    async def test_send_packet_enforces_read_timeout(self):
        writer = FakeRadSecWriter()

        async def open_connection():
            return FakeRadSecReader(delay=1), writer

        self.client.retries = 1
        self.client._open_connection = open_connection

        reply = await self.client._send_packet(FakeRadSecPacket())

        self.assertIsNone(reply)
        self.assertTrue(writer.closed)

    async def test_send_packet_reconnects_after_stream_failure(self):
        connections = []

        async def open_connection():
            writer = FakeRadSecWriter()
            connections.append(writer)
            if len(connections) == 1:
                return (
                    FakeRadSecReader(
                        exception=asyncio.IncompleteReadError(
                            partial=b"", expected=4
                        )
                    ),
                    writer,
                )
            return FakeRadSecReader(raw_radius_response()), writer

        self.client.retries = 2
        self.client._open_connection = open_connection

        reply = await self.client._send_packet(FakeRadSecPacket())

        self.assertIsNotNone(reply)
        self.assertEqual(len(connections), 2)
        self.assertTrue(connections[0].closed)


class AuthPacketHandlingTests(ServerTests):
    def setUp(self):
        super().setUp()
        self.packet = self.create_auth_packet()

    def create_auth_packet(self):
        packet = self.client.create_auth_packet(
            code=PacketType.AccessRequest, User_Name="wichert"
        )
        packet["NAS-IP-Address"] = "192.168.1.10"
        packet["NAS-Port"] = 0
        packet["Service-Type"] = "Login-User"
        packet["NAS-Identifier"] = "trillian"
        packet["Called-Station-Id"] = "00-04-5F-00-0F-D1"
        packet["Calling-Station-Id"] = "00-01-24-80-B3-9C"
        packet["Framed-IP-Address"] = "10.0.0.100"
        return packet

    async def test_handle_auth_packet(self):
        reply = await self.server.handle_access_request(self.packet)
        self.assertEqual(reply.code, PacketType.AccessAccept)


class AcctPacketHandlingTests(ServerTests):
    def setUp(self):
        super().setUp()
        self.packet = self.create_acct_packet()

    def create_acct_packet(self):
        packet = self.client.create_acct_packet(
            code=PacketType.AccountingRequest, User_Name="wichert"
        )
        packet["NAS-IP-Address"] = "192.168.1.10"
        packet["NAS-Port"] = 0
        packet["Service-Type"] = "Login-User"
        packet["NAS-Identifier"] = "trillian"
        packet["Called-Station-Id"] = "00-04-5F-00-0F-D1"
        packet["Calling-Station-Id"] = "00-01-24-80-B3-9C"
        packet["Framed-IP-Address"] = "10.0.0.100"
        packet["Acct-Status-Type"] = "Start"
        return packet

    async def test_handle_acct_packet(self):
        reply = await self.server.handle_accounting(self.packet)
        self.assertEqual(reply.code, PacketType.AccountingResponse)
