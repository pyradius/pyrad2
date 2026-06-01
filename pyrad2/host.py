import socket
from typing import Optional

from pyrad2 import packet
from pyrad2.dictionary import Dictionary


class Host:
    """Generic RADIUS capable host."""

    def __init__(
        self,
        authport: int = 1812,
        acctport: int = 1813,
        coaport: int = 3799,
        dict: Optional[Dictionary] = None,
    ):
        """Initializes a host.

        Args:
            authport (int): port to listen on for authentication packets
            acctport (int): port to listen on for accounting packets
            coaport (int): port to listen on for CoA packets
            dict (Dictionary): RADIUS dictionary
        """
        self.dict = dict
        self.authport = authport
        self.acctport = acctport
        self.coaport = coaport

    def create_packet(self, **args) -> packet.Packet:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS authentication
        packet which can be used to communicate with the RADIUS server
        this client talks to. This is initializing the new packet with
        the dictionary and secret used for the client.

        Returns:
            pyrad2.packet.Packet: A new empty packet instance.
        """
        return packet.Packet(dict=self.dict, **args)

    def create_auth_packet(self, **args) -> packet.Packet:
        """Create a new authentication RADIUS packet.
        This utility function creates a new RADIUS authentication
        packet which can be used to communicate with the RADIUS server
        this client talks to. This is initializing the new packet with
        the dictionary and secret used for the client.

        Returns:
            pyrad2.packet.Packet: A new empty packet instance.
        """
        return packet.AuthPacket(dict=self.dict, **args)

    def create_acct_packet(self, **args) -> packet.Packet:
        """Create a new accounting RADIUS packet.
        This utility function creates a new accounting RADIUS packet
        which can be used to communicate with the RADIUS server this
        client talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance.
        """
        return packet.AcctPacket(dict=self.dict, **args)

    def create_coa_packet(self, **args) -> packet.Packet:
        """Create a new CoA RADIUS packet.
        This utility function creates a new CoA RADIUS packet
        which can be used to communicate with the RADIUS server this
        client talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            packet.Packet: A new empty packet instance.
        """
        return packet.CoAPacket(dict=self.dict, **args)

    def create_status_packet(self, **args) -> packet.Packet:
        """Create a new Status-Server RADIUS packet.

        Status-Server packets are used for RFC 5997 health checks and always
        include Message-Authenticator when encoded for transmission.
        """
        return packet.StatusPacket(dict=self.dict, **args)

    def send_packet(self, fd: socket.socket, pkt) -> None:
        """Send a packet.

        Args:
            fd (socket.socket): Socket to send packet with
            pkt (packet.Packet): The packet instance
        """
        fd.sendto(pkt.request_packet(), pkt.source)

    def send_reply_packet(self, fd: socket.socket, pkt: packet.Packet) -> None:
        """Send a packet.

        Args:
            fd (socket.socket): Socket to send packet with
            pkt (packet.Packet): The packet instance
        """
        fd.sendto(pkt.reply_packet(), pkt.source)  # type: ignore
