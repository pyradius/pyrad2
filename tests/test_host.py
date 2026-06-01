import unittest
from pyrad2.host import Host
from pyrad2.packet import Packet
from pyrad2.packet import AuthPacket
from pyrad2.packet import AcctPacket
from pyrad2.packet import StatusPacket


class ConstructionTests(unittest.TestCase):
    def testSimpleConstruction(self):
        host = Host()
        self.assertEqual(host.authport, 1812)
        self.assertEqual(host.acctport, 1813)

    def testParameterOrder(self):
        host = Host(123, 456, 789, 101)
        self.assertEqual(host.authport, 123)
        self.assertEqual(host.acctport, 456)
        self.assertEqual(host.coaport, 789)
        self.assertEqual(host.dict, 101)

    def testNamedParameters(self):
        host = Host(authport=123, acctport=456, coaport=789, dict=101)
        self.assertEqual(host.authport, 123)
        self.assertEqual(host.acctport, 456)
        self.assertEqual(host.coaport, 789)
        self.assertEqual(host.dict, 101)


class PacketCreationTests(unittest.TestCase):
    def setUp(self):
        self.host = Host()

    def testCreatePacket(self):
        packet = self.host.create_packet(id=15)
        self.assertTrue(isinstance(packet, Packet))
        self.assertTrue(packet.dict is self.host.dict)
        self.assertEqual(packet.id, 15)

    def testCreateAuthPacket(self):
        packet = self.host.create_auth_packet(id=15)
        self.assertTrue(isinstance(packet, AuthPacket))
        self.assertTrue(packet.dict is self.host.dict)
        self.assertEqual(packet.id, 15)

    def testCreateAcctPacket(self):
        packet = self.host.create_acct_packet(id=15)
        self.assertTrue(isinstance(packet, AcctPacket))
        self.assertTrue(packet.dict is self.host.dict)
        self.assertEqual(packet.id, 15)

    def testCreateStatusPacket(self):
        packet = self.host.create_status_packet(id=15)
        self.assertTrue(isinstance(packet, StatusPacket))
        self.assertTrue(packet.dict is self.host.dict)
        self.assertEqual(packet.id, 15)


class MockPacket:
    packet = object()
    replypacket = object()
    source = object()

    def request_packet(self):
        return self.packet

    def reply_packet(self):
        return self.replypacket


class MockFd:
    data = None
    target = None

    def sendto(self, data, target):
        self.data = data
        self.target = target


class PacketSendTest(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        self.fd = MockFd()
        self.packet = MockPacket()

    def testSendPacket(self):
        self.host.send_packet(self.fd, self.packet)
        self.assertTrue(self.fd.data is self.packet.packet)
        self.assertTrue(self.fd.target is self.packet.source)

    def testSendReplyPacket(self):
        self.host.send_reply_packet(self.fd, self.packet)
        self.assertTrue(self.fd.data is self.packet.replypacket)
        self.assertTrue(self.fd.target is self.packet.source)
