import select
import socket

import pytest

from pyrad2.constants import PacketType
from pyrad2.proxy import Proxy
from pyrad2.server import Server, ServerPacketError

from .mock import (
    MockClassMethod,
    MockFd,
    MockPoll,
    MockSocket,
    UnmockClassMethods,
)


class _TrivialObject:
    """dummy object"""


@pytest.mark.skipif(not hasattr(select, "poll"), reason="select.poll not available")
class TestSocket:
    def setup_method(self):
        self._orgsocket = socket.socket
        socket.socket = MockSocket
        self.proxy = Proxy()
        self.proxy._fdmap = {}

    def teardown_method(self):
        socket.socket = self._orgsocket

    def test_proxy_fd(self):
        self.proxy._poll = MockPoll()
        self.proxy._prepare_sockets()
        assert isinstance(self.proxy._proxyfd, MockSocket)
        assert list(self.proxy._fdmap.keys()) == [1]
        assert self.proxy._poll.registry == {
            1: select.POLLIN | select.POLLPRI | select.POLLERR
        }


class TestProxyPacketHandling:
    def setup_method(self):
        self.proxy = Proxy()
        self.proxy.hosts["host"] = _TrivialObject()
        self.proxy.hosts["host"].secret = "supersecret"
        self.packet = _TrivialObject()
        self.packet.code = PacketType.AccessAccept
        self.packet.source = ("host", "port")

    def test_handle_proxy_packet_unknown_host(self):
        self.packet.source = ("stranger", "port")
        with pytest.raises(ServerPacketError, match="unknown host"):
            self.proxy._handle_proxy_packet(self.packet)

    def test_handle_proxy_packet_sets_secret(self):
        self.proxy._handle_proxy_packet(self.packet)
        assert self.packet.secret == "supersecret"

    def test_handle_proxy_packet_rejects_non_response_code(self):
        self.packet.code = PacketType.AccessRequest
        with pytest.raises(ServerPacketError, match="non-response"):
            self.proxy._handle_proxy_packet(self.packet)


class TestProcessInput:
    def setup_method(self):
        self.proxy = Proxy()
        self.proxy._proxyfd = MockFd()

    def teardown_method(self):
        UnmockClassMethods(Proxy)
        UnmockClassMethods(Server)

    def test_process_input_non_proxy_port(self):
        fd = MockFd(fd=111)
        MockClassMethod(Server, "_process_input")
        self.proxy._process_input(fd)
        assert self.proxy.called == [("_process_input", (fd,), {})]

    def test_process_input(self):
        MockClassMethod(Proxy, "_grab_packet")
        MockClassMethod(Proxy, "_handle_proxy_packet")
        self.proxy._process_input(self.proxy._proxyfd)
        assert [x[0] for x in self.proxy.called] == [
            "_grab_packet",
            "_handle_proxy_packet",
        ]
