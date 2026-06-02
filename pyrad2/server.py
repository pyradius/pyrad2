import os

if os.name == "nt":
    import selectors
else:
    import select
import socket
from dataclasses import dataclass
from typing import Callable, Optional

from loguru import logger

from pyrad2 import dedup, host, packet
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import ServerPacketError
from pyrad2.constants import PacketType
from pyrad2.router import RequestRouter


@dataclass
class RemoteHost:
    """Remote RADIUS capable host we can talk to.

    Args:
        address (str): IP address.
        secret (bytes): RADIUS secret. If connecting to a RadSec server, the secret should be `radsec`.
        name (str): Short name (used for logging only).
        authport (int): Port used for authentication packets.
        acctport (int): Port used for accounting packets.
        coaport (int): Port used for CoA packets.
    """

    address: str
    secret: bytes
    name: str
    authport: int = 1812
    acctport: int = 1813
    coaport: int = 3799


class Server(host.Host):
    """Basic RADIUS server.
    This class implements the basics of a RADIUS server. It takes care
    of the details of receiving and decoding requests; processing of
    the requests should be done by overloading the appropriate methods
    in derived classes.

    Attributes:
        hosts (dict): Hosts who are allowed to talk to us. Dictionary of Host class instances.
        _poll (select.poll): Poll object for network sockets.
        _fdmap (dict): Map of file descriptors to network sockets.
        MaxPacketSize (int): Maximum size of a RADIUS packet. (class variable)
    """

    MAX_PACKET_SIZE = 8192

    def __init__(
        self,
        addresses: Optional[list[str]] = None,
        authport: int = 1812,
        acctport: int = 1813,
        coaport: int = 3799,
        hosts: Optional[dict] = None,
        dict: Optional[Dictionary] = None,
        auth_enabled: bool = True,
        acct_enabled: bool = True,
        coa_enabled: bool = False,
        require_message_authenticator: bool = True,
        require_eap_message_authenticator: bool = True,
        enable_pkt_verify: bool = True,
        dedup_enabled: bool = True,
        dedup_ttl: float = 30.0,
        dedup_max_entries: int = 4096,
        dedup_cache: Optional[dedup.ResponseCache] = None,
    ):
        """Initializes a sync server.

        Args:
            addresses (Sequence[str]): IP addresses to listen on.
            authport (int): Port to listen on for authentication packets.
            acctport (int): Port to listen on for accounting packets.
            coaport (int): Port to listen on for CoA packets.
            hosts (dict[str, RemoteHost]): Hosts who we can talk to. A dictionary mapping IP to RemoteHost class instances.
            dict (Dictionary): RADIUS dictionary to use.
            auth_enabled (bool): Enable auth server (default: True).
            acct_enabled (bool): Enable accounting server (default: True).
            coa_enabled (bool): Enable CoA server (default: False).
            require_message_authenticator (bool): Require
                Message-Authenticator on incoming packets (default: True).
                Mitigates BlastRADIUS (CVE-2024-3596). Disable only to
                bridge legacy NASes that don't emit the attribute.
            require_eap_message_authenticator (bool): Require
                Message-Authenticator on packets containing EAP-Message.
            enable_pkt_verify (bool): Verify the Request Authenticator on
                every received packet before dispatch (default: True).
                Mirrors ``ServerAsync.enable_pkt_verify``. Disable only to
                bridge legacy NASes that emit malformed authenticators.
            dedup_enabled (bool): Enable RFC 5080 duplicate detection and
                response caching (default: True). Retransmissions of an
                Access-Request, Accounting-Request, CoA-Request, or
                Disconnect-Request will be answered by replaying the cached
                reply bytes instead of re-running the handler.
            dedup_ttl (float): Lifetime in seconds of a cached reply.
            dedup_max_entries (int): Maximum number of cached replies before
                LRU eviction kicks in.
            dedup_cache (ResponseCache): Provide a pre-built cache to share
                between servers or to inject a custom clock for tests.
        """
        super().__init__(authport, acctport, coaport, dict)

        self.hosts = hosts or {}
        self.auth_enabled = auth_enabled
        self.authfds: list[socket.socket] = []
        self.acct_enabled = acct_enabled
        self.acctfds: list = []
        self.coa_enabled = coa_enabled
        self.coafds: list = []
        self.require_message_authenticator = require_message_authenticator
        self.require_eap_message_authenticator = require_eap_message_authenticator
        self.enable_pkt_verify = enable_pkt_verify
        if dedup_cache is not None:
            self._dedup_cache: Optional[dedup.ResponseCache] = dedup_cache
        elif dedup_enabled:
            self._dedup_cache = dedup.ResponseCache(
                ttl=dedup_ttl, max_entries=dedup_max_entries
            )
        else:
            self._dedup_cache = None

        # Shared transport-neutral dispatch helper. The async server owns
        # its own RequestRouter instance with the same fields, so the
        # two transports can't drift apart on policy.
        self._router = RequestRouter(
            hosts=self.hosts,
            dictionary=self.dict,
            enable_pkt_verify=self.enable_pkt_verify,
            require_message_authenticator=self.require_message_authenticator,
            require_eap_message_authenticator=self.require_eap_message_authenticator,
            dedup_cache=self._dedup_cache,
        )

        if addresses:
            for addr in addresses:
                self.bind_to_address(addr)

    def _validate_message_authenticator_policy(self, pkt: packet.Packet) -> None:
        """Validate incoming Message-Authenticator policy for a packet."""
        self._router.validate_message_authenticator_policy(pkt)

    def _send_status_response(self, pkt: packet.Packet, code: PacketType) -> None:
        """Reply to Status-Server without invoking normal request handlers."""
        reply = self.create_reply_packet(pkt, code=code)
        if hasattr(pkt, "fd"):
            self.send_reply_packet(pkt.fd, reply)

    def _handle_status_packet(self, pkt: packet.Packet, code: PacketType) -> bool:
        """Handle Status-Server packets before normal request dispatch."""
        if pkt.code != PacketType.StatusServer:
            return False
        self._validate_message_authenticator_policy(pkt)
        logger.debug(
            "Received Status-Server from {}; replying with {}",
            getattr(pkt, "source", None),
            code.name,
        )
        self._send_status_response(pkt, code)
        return True

    def _get_addr_info(
        self, addr: str
    ) -> set[tuple[socket.AddressFamily, str | int]] | list:
        """Use getaddrinfo to lookup all addresses for each address.

        Returns a list of tuples or an empty list:
          [(family, address)]

        Args:
            adddr (str): IP address to lookup
        """
        results = set()
        # ``port=None`` skips the service lookup entirely; ``SOCK_DGRAM``
        # filters the results to UDP (RADIUS) so we don't iterate over
        # duplicated TCP+UDP entries.
        try:
            tmp = socket.getaddrinfo(addr, None, type=socket.SOCK_DGRAM)
        except socket.gaierror:
            return []

        for el in tmp:
            results.add((el[0], el[4][0]))

        return results

    def bind_to_address(self, addr: str) -> None:
        """Add an address to listen on a specific interface.
        String "0.0.0.0" indicates you want to listen on all interfaces.

        Args:
            addr (str): IP address to listen on
        """
        addr_family = self._get_addr_info(addr)
        for family, address in addr_family:
            if self.auth_enabled:
                authfd = socket.socket(family, socket.SOCK_DGRAM)
                authfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                authfd.bind((address, self.authport))
                self.authfds.append(authfd)

            if self.acct_enabled:
                acctfd = socket.socket(family, socket.SOCK_DGRAM)
                acctfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                acctfd.bind((address, self.acctport))
                self.acctfds.append(acctfd)

            if self.coa_enabled:
                coafd = socket.socket(family, socket.SOCK_DGRAM)
                coafd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                coafd.bind((address, self.coaport))
                self.coafds.append(coafd)

    def handle_auth_packet(self, pkt: packet.Packet):
        """Authentication packet handler.
        This is an empty function that is called when a valid
        authentication packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            pkt (packet.Packet): Packet to process
        """

    def handle_acct_packet(self, pkt: packet.Packet):
        """Accounting packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            pkt (packet.Packet): Packet to process
        """

    def handle_coa_packet(self, pkt: packet.Packet):
        """CoA packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            pkt (packet.Packet): Packet to process
        """

    def handle_disconnect_packet(self, pkt: packet.Packet):
        """CoA packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            pkt (packet.Packet): Packet to process
        """

    def _dedup_dispatch(
        self, pkt: packet.Packet, handler: Callable[[packet.Packet], None]
    ) -> None:
        """Wrap ``handler(pkt)`` with RFC 5080 dedup.

        On a cached duplicate, replays the stored reply bytes via the
        request's socket and skips the handler entirely. On an in-flight
        duplicate, drops silently. Otherwise runs the handler and lets
        ``send_reply_packet`` populate the cache.
        """
        key = self._router.dedup_key_for(pkt)
        fd = getattr(pkt, "fd", None)

        def _resend(raw: bytes) -> None:
            if fd is not None:
                fd.sendto(raw, pkt.source)

        action = self._router.dedup_consult(key, _resend)
        if action is dedup.DispatchAction.DROP:
            logger.debug("Dropping duplicate in-flight request from {}", pkt.source)
            return
        if action is dedup.DispatchAction.RESENT:
            logger.debug(
                "Resent cached reply for duplicate request from {}", pkt.source
            )
            return

        if key is not None:
            pkt._dedup_key = key  # type: ignore[attr-defined]
        try:
            handler(pkt)
        finally:
            self._router.dedup_drop_in_flight(key)

    def _lookup_secret(self, addr: str) -> bytes:
        """Return the shared secret for ``addr`` or raise ``ServerPacketError``."""
        return self._router.lookup_secret(addr)

    def _add_secret(self, pkt: packet.Packet) -> None:
        """Backwards-compatible shim: set ``pkt.secret`` from ``self.hosts``.

        Kept for subclasses that override or call it directly. ``_grab_packet``
        now seeds the secret during decode, so this is usually a no-op.
        """
        pkt.secret = self._router.lookup_secret(pkt.source[0])

    def _verify_request_authenticator(self, pkt: packet.Packet) -> None:
        """Run the per-code Request Authenticator check before dispatch."""
        self._router.verify_request(pkt)

    def _handle_auth_packet(self, pkt: packet.Packet) -> None:
        """Process a packet received on the authentication port.
        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        Args:
            pkt (packet.Packet): Packet to process
        """
        self._add_secret(pkt)
        if self._handle_status_packet(pkt, PacketType.AccessAccept):
            return
        if pkt.code != PacketType.AccessRequest:
            raise ServerPacketError(
                "Received non-authentication packet on authentication port"
            )
        self._verify_request_authenticator(pkt)
        self._validate_message_authenticator_policy(pkt)
        self._dedup_dispatch(pkt, self.handle_auth_packet)

    def _handle_acct_packet(self, pkt: packet.Packet) -> None:
        """Process a packet received on the accounting port.
        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        Args:
            pkt (packet.Packet): Packet to process
        """
        self._add_secret(pkt)
        if self._handle_status_packet(pkt, PacketType.AccountingResponse):
            return
        if pkt.code not in [
            PacketType.AccountingRequest,
            PacketType.AccountingResponse,
        ]:
            raise ServerPacketError("Received non-accounting packet on accounting port")
        self._verify_request_authenticator(pkt)
        self._validate_message_authenticator_policy(pkt)
        self._dedup_dispatch(pkt, self.handle_acct_packet)

    def _handle_coa_packet(self, pkt: packet.Packet) -> None:
        """Process a packet received on the coa port.
        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        Args:
            pkt (packet.Packet): Packet to process
        """
        self._add_secret(pkt)
        if pkt.code == PacketType.CoARequest:
            self._verify_request_authenticator(pkt)
            self._validate_message_authenticator_policy(pkt)
            self._dedup_dispatch(pkt, self.handle_coa_packet)
        elif pkt.code == PacketType.DisconnectRequest:
            self._verify_request_authenticator(pkt)
            self._validate_message_authenticator_policy(pkt)
            self._dedup_dispatch(pkt, self.handle_disconnect_packet)
        else:
            raise ServerPacketError("Received non-coa packet on coa port")

    def _grab_packet(self, fd: socket.socket) -> packet.Packet:
        """Read a packet from a network connection.
        This method assumes there is data waiting to be read.

        Looks up the source address against ``self.hosts`` first so unknown
        sources are dropped before any attribute parsing runs, and parses
        the packet with the host's real shared secret (which lets
        ``verify_*_request`` MD5 checks pass without a re-parse).

        Args:
            fd (socket.socket): Socket to read packet from

        Returns:
            packet.Packet: RADIUS packet
        """
        (data, source) = fd.recvfrom(self.MAX_PACKET_SIZE)
        secret = self._router.lookup_secret(source[0])
        pkt = self._router.parse(data, secret)
        pkt.source = source
        # Stash the originating fd on the packet so ``send_reply_packet``
        # and the dedup-cache resend path can route the reply back over
        # the same socket without re-discovering it.
        pkt.fd = fd  # type: ignore[attr-defined]
        return pkt

    def _prepare_sockets(self) -> None:
        """Prepare all sockets to receive packets."""
        for fd in self.authfds + self.acctfds + self.coafds:
            self._fdmap[fd.fileno()] = fd
            if os.name == "nt":
                self._sel.register(fd.fileno(), selectors.EVENT_READ)
            else:
                self._poll.register(
                    fd.fileno(), select.POLLIN | select.POLLPRI | select.POLLERR
                )
        # Membership-tested per packet in ``_process_input``; sets make
        # that O(1) instead of an O(N) list scan.
        if self.auth_enabled:
            self._realauthfds = {x.fileno() for x in self.authfds}
        if self.acct_enabled:
            self._realacctfds = {x.fileno() for x in self.acctfds}
        if self.coa_enabled:
            self._realcoafds = {x.fileno() for x in self.coafds}

    def create_reply_packet(self, pkt: packet.Packet, **attributes) -> packet.Packet:
        """Create a reply packet.
        Create a new packet which can be returned as a reply to a received
        packet.

        Args:
            pkt (packet.Packet): Packet to process
        """
        reply = pkt.create_reply(**attributes)
        reply.source = pkt.source
        self._router.prepare_reply(pkt, reply)
        # Carry the request's dedup key forward so send_reply_packet can
        # cache the resulting bytes without re-deriving the key.
        self._router.attach_dedup_key(pkt, reply)
        return reply

    def send_reply_packet(self, fd: socket.socket, pkt: packet.Packet) -> None:
        """Send a reply packet after applying Message-Authenticator policy."""
        self._router.force_reply_ma(pkt)
        # Encode once: we need the exact bytes for RFC 5080 replay so a
        # retransmission gets a byte-identical answer (which matters for
        # the EAP State attribute and the Message-Authenticator).
        raw = pkt.reply_packet()
        fd.sendto(raw, pkt.source)  # type: ignore[call-overload]
        self._router.record_reply(pkt, raw)

    def _process_input(self, fd: socket.socket) -> None:
        """Process available data.
        If this packet should be dropped instead of processed a
        PacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        This function calls either handle_auth_packet() or
        handle_acct_packet() depending on which socket is being
        processed.

        Args:
            fd (socket.socket): Socket to read the packet from
        """
        if self.auth_enabled and fd.fileno() in self._realauthfds:
            pkt = self._grab_packet(fd)
            self._handle_auth_packet(pkt)
        elif self.acct_enabled and fd.fileno() in self._realacctfds:
            pkt = self._grab_packet(fd)
            self._handle_acct_packet(pkt)
        elif self.coa_enabled:
            pkt = self._grab_packet(fd)
            self._handle_coa_packet(pkt)
        else:
            raise ServerPacketError("Received packet for unknown handler")

    def run(self) -> None:
        """Main loop.
        This method is the main loop for a RADIUS server. It waits
        for packets to arrive via the network and calls other methods
        to process them.
        """
        if os.name == "nt":
            self._sel = selectors.DefaultSelector()
        else:
            self._poll = select.poll()
        self._fdmap: dict[int, socket.socket] = {}
        self._prepare_sockets()

        while True:
            if os.name == "nt":
                for key, mask in self._sel.select(timeout=1):
                    if mask & selectors.EVENT_READ:
                        try:
                            fdo = self._fdmap[key.fd]
                            self._process_input(fdo)
                        except ServerPacketError as err:
                            logger.info("Dropping packet: " + str(err))
                        except packet.PacketError as err:
                            logger.info("Received a broken packet: " + str(err))
                    else:
                        logger.error("Unexpected event in server main loop")
            else:
                for fd, event in self._poll.poll():
                    if event == select.POLLIN:
                        try:
                            fdo = self._fdmap[fd]
                            self._process_input(fdo)
                        except ServerPacketError as err:
                            logger.info("Dropping packet: " + str(err))
                        except packet.PacketError as err:
                            logger.info("Received a broken packet: " + str(err))
                    else:
                        logger.error("Unexpected event in server main loop")
