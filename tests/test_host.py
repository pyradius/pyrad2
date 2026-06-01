from pyrad2.host import Host
from pyrad2.packet import AcctPacket, AuthPacket, Packet, StatusPacket


class TestHostConstruction:
    def test_simple_construction(self):
        host = Host()
        assert host.authport == 1812
        assert host.acctport == 1813

    def test_parameter_order(self):
        host = Host(123, 456, 789, 101)
        assert host.authport == 123
        assert host.acctport == 456
        assert host.coaport == 789
        assert host.dict == 101

    def test_named_parameters(self):
        host = Host(authport=123, acctport=456, coaport=789, dict=101)
        assert host.authport == 123
        assert host.acctport == 456
        assert host.coaport == 789
        assert host.dict == 101


class TestPacketCreation:
    def setup_method(self):
        self.host = Host()

    def test_create_packet(self):
        packet = self.host.create_packet(id=15)
        assert isinstance(packet, Packet)
        assert packet.dict is self.host.dict
        assert packet.id == 15

    def test_create_auth_packet(self):
        packet = self.host.create_auth_packet(id=15)
        assert isinstance(packet, AuthPacket)
        assert packet.dict is self.host.dict
        assert packet.id == 15

    def test_create_acct_packet(self):
        packet = self.host.create_acct_packet(id=15)
        assert isinstance(packet, AcctPacket)
        assert packet.dict is self.host.dict
        assert packet.id == 15

    def test_create_status_packet(self):
        packet = self.host.create_status_packet(id=15)
        assert isinstance(packet, StatusPacket)
        assert packet.dict is self.host.dict
        assert packet.id == 15


class _MockPacket:
    packet = object()
    replypacket = object()
    source = object()

    def request_packet(self):
        return self.packet

    def reply_packet(self):
        return self.replypacket


class _MockFd:
    data = None
    target = None

    def sendto(self, data, target):
        self.data = data
        self.target = target


class TestPacketSend:
    def setup_method(self):
        self.host = Host()
        self.fd = _MockFd()
        self.packet = _MockPacket()

    def test_send_packet(self):
        self.host.send_packet(self.fd, self.packet)
        assert self.fd.data is self.packet.packet
        assert self.fd.target is self.packet.source

    def test_send_reply_packet(self):
        self.host.send_reply_packet(self.fd, self.packet)
        assert self.fd.data is self.packet.replypacket
        assert self.fd.target is self.packet.source
