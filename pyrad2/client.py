import os

if os.name == "nt":
    import selectors
else:
    import select
import socket
import time
from typing import Optional

from pyrad2 import eap, host, packet
from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import Timeout


class Client(host.Host):
    """Basic RADIUS client.
    This class implements a basic RADIUS client. It can send requests
    to a RADIUS server, taking care of timeouts and retries, and
    validate its replies.
    """

    def __init__(
        self,
        server: str,
        authport: int = 1812,
        acctport: int = 1813,
        coaport: int = 3799,
        secret: bytes = b"",
        dict: Optional[Dictionary] = None,
        retries: int = 3,
        timeout: int = 5,
        enforce_ma: bool = True,
    ):
        """Initializes a RADIUS client.

        Args:
            server (str): Hostname or IP address of the RADIUS server.
            authport (int): Port to use for authentication packets.
            acctport (int): Port to use for accounting packets.
            coaport (int): Port to use for CoA packets.
            secret (bytes): RADIUS secret.
            dict (pyrad.dictionary.Dictionary): RADIUS dictionary.
            retries (int): Number of times to retry sending a RADIUS request.
            timeout (int): Number of seconds to wait for an answer.
            enforce_ma (bool): Enforce Message-Authenticator on requests
                and replies (default: True). Mitigates BlastRADIUS
                (CVE-2024-3596). Disable only when talking to a legacy
                server that can't process the attribute.
        """
        super().__init__(authport, acctport, coaport, dict)

        self.server = server
        self.secret = secret
        self.retries = retries
        self.timeout = timeout
        self.enforce_ma = enforce_ma

        if os.name == "nt":
            self._sel = selectors.DefaultSelector()
        else:
            self._poll = select.poll()
        self._socket: Optional[socket.socket] = None

    def _prepare_outgoing_packet(self, pkt: packet.PacketImplementation) -> None:
        """Apply Message-Authenticator policy before a packet is sent."""
        packet.prepare_request_message_authenticator(
            pkt,
            require_message_authenticator=self.enforce_ma,
        )

    def bind(self, addr: str | tuple) -> None:
        """Bind socket to an address.
        Binding the socket used for communicating to an address can be
        usefull when working on a machine with multiple addresses.

        Args:
            addr (str | tuple): network address (hostname or IP) and port to bind to
        """
        self._close_socket()
        self._socket_open()
        if self._socket:
            self._socket.bind(addr)
        else:
            raise RuntimeError("No socket present")

    def _socket_open(self) -> None:
        try:
            family = socket.getaddrinfo(self.server, 80)[0][0]
        except Exception:
            family = socket.AF_INET
        if not self._socket:
            self._socket = socket.socket(family, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if os.name == "nt":
                self._sel.register(self._socket, selectors.EVENT_READ)
            else:
                self._poll.register(self._socket, select.POLLIN)

    def _close_socket(self) -> None:
        if self._socket:
            if os.name == "nt":
                self._sel.unregister(self._socket)
            else:
                self._poll.unregister(self._socket)
            self._socket.close()
            self._socket = None

    def create_auth_packet(self, **args) -> packet.Packet:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance
        """
        ma_enabled = True if self.enforce_ma else False
        return super().create_auth_packet(
            secret=self.secret, message_authenticator=ma_enabled, **args
        )

    def create_acct_packet(self, **args) -> packet.Packet:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance
        """
        return super().create_acct_packet(secret=self.secret, **args)

    def create_coa_packet(self, **args) -> packet.Packet:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance
        """
        return super().create_coa_packet(secret=self.secret, **args)

    def create_status_packet(self, **args) -> packet.StatusPacket:
        """Create an RFC 5997 Status-Server health-check packet."""
        return packet.StatusPacket(dict=self.dict, secret=self.secret, **args)

    def _status_port(self, port: str) -> int:
        """Return the UDP port used for a Status-Server health check."""
        if port == "auth":
            return self.authport
        if port == "acct":
            return self.acctport
        raise ValueError("Status-Server port must be 'auth' or 'acct'")

    def send_status_packet(
        self, pkt: Optional[packet.StatusPacket] = None, *, port: str = "auth"
    ) -> packet.Packet:
        """Send a Status-Server packet to the auth or accounting port."""
        if pkt is None:
            pkt = self.create_status_packet()
        return self._send_packet(pkt, self._status_port(port))

    def _send_packet(self, pkt: packet.PacketImplementation, port: int):
        """Send a packet to a RADIUS server.

        Args:
            pkt (packet.Packet): The packet to send
            port (int): UDP port to send packet to

        Returns:
            packet.Packet: The reply packet received

        Raises:
            Timeout: RADIUS server does not reply
        """
        self._socket_open()

        for attempt in range(self.retries):
            if attempt and pkt.code == PacketType.AccountingRequest:
                if "Acct-Delay-Time" in pkt:
                    pkt["Acct-Delay-Time"] = pkt["Acct-Delay-Time"][0] + self.timeout
                else:
                    pkt["Acct-Delay-Time"] = self.timeout

            now = time.time()
            waitto = now + self.timeout

            if not self._socket:
                raise RuntimeError("No socket present")

            self._prepare_outgoing_packet(pkt)
            self._socket.sendto(pkt.request_packet(), (self.server, port))

            while now < waitto:
                rawreply = None

                if os.name == "nt":
                    for key, mask in self._sel.select(timeout=(waitto - now)):
                        if mask & selectors.EVENT_READ:
                            if isinstance(key.fileobj, socket.socket):
                                rawreply = key.fileobj.recv(4096)

                else:
                    ready = self._poll.poll((waitto - now) * 1000)

                    if ready:
                        rawreply = self._socket.recv(4096)

                if not rawreply:
                    now = time.time()
                    continue

                try:
                    reply = pkt.create_reply(packet=rawreply)
                    if pkt.verify_reply(reply, rawreply, enforce_ma=self.enforce_ma):
                        if hasattr(pkt, "authenticator"):
                            reply.request_authenticator = pkt.authenticator

                        return reply
                except packet.PacketError:
                    pass

                now = time.time()

        raise Timeout

    def send_packet(self, pkt: packet.PacketImplementation) -> packet.Packet:  # type: ignore
        """Send a packet to a RADIUS server.

        Args:
            pkt (packet.Packet): Packet to send

        Returns:
            packet.Packet: The reply packet received

        Raises:
            Timeout: RADIUS server does not reply
        """
        if isinstance(pkt, packet.StatusPacket):
            return self.send_status_packet(pkt)
        if isinstance(pkt, packet.AuthPacket):
            if pkt.auth_type == "eap-md5":
                eap.inject_eap_identity(pkt)
            reply = self._send_packet(pkt, self.authport)
            if (
                reply
                and reply.code == PacketType.AccessChallenge
                and pkt.auth_type == "eap-md5"
            ):
                eap.apply_eap_md5_challenge(pkt, reply)
                reply = self._send_packet(pkt, self.authport)
            return reply
        elif isinstance(pkt, packet.CoAPacket):
            return self._send_packet(pkt, self.coaport)
        else:
            return self._send_packet(pkt, self.acctport)
