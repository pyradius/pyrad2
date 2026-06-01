import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from loguru import logger

from pyrad2 import dedup
from pyrad2.constants import ErrorCause, PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.packet import Packet, StatusPacket
from pyrad2.router import RequestRouter, ServerType
from pyrad2.server import RemoteHost, ServerPacketError

# Re-export so existing imports of ``pyrad2.server_async.ServerType``
# keep working after the move to ``pyrad2.router``.
__all__ = ["DatagramProtocolServer", "RemoteHost", "ServerAsync", "ServerType"]


ERROR_CAUSE_ATTRIBUTE = 101


class DatagramProtocolServer(asyncio.DatagramProtocol):
    def __init__(
        self,
        ip: str,
        port: int,
        server: "ServerAsync",
        server_type: ServerType,
        hosts: dict[str, RemoteHost],
        request_callback: Callable,
    ):
        self.ip = ip
        self.port = port
        self.server = server
        self.hosts = hosts
        self.server_type = server_type
        self.request_callback = request_callback
        self.transport: asyncio.DatagramTransport

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore
        logger.info("[{}:{}] Transport created", self.ip, self.port)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.warning("[{}:{}] Connection lost: {}", self.ip, self.port, exc)
        else:
            logger.info("[{}:{}] Transport closed", self.ip, self.port)

    def send_response(self, reply: Packet, addr: tuple[str | Any, int]) -> None:
        self.server.prepare_reply_packet(reply)
        # Encode once and cache the bytes for RFC 5080 replay: a
        # retransmission must receive a byte-identical reply (matters
        # for EAP State and Message-Authenticator).
        raw = reply.reply_packet()
        self.transport.sendto(raw, addr)
        self.server._router.record_reply(reply, raw)

    def _handle_status_server(
        self, data: bytes, secret: bytes, addr: tuple[str | Any, int]
    ) -> None:
        """Reply to Status-Server without invoking normal request callbacks."""
        req = StatusPacket(secret=secret, dict=self.server.dict, packet=data)
        self.server._router.validate_message_authenticator_policy(req)
        reply = self.server.create_status_response(req, self.server_type)
        logger.debug(
            "[{}:{}] Received Status-Server from {}; replying with {}",
            self.ip,
            self.port,
            addr,
            PacketType(reply.code).name,
        )
        self.send_response(reply, addr)

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]):
        logger.debug(
            "[{}:{}] Received {} bytes from {}", self.ip, self.port, len(data), addr
        )
        receive_date = datetime.now(timezone.utc)
        router = self.server._router

        # The protocol's own ``hosts`` mapping is authoritative for lookup
        # (it can be a per-listener subset of the server's hosts). The
        # router's parse / verify / MA-policy chain then uses the secret
        # we resolved here.
        remote_host = self.hosts.get(addr[0]) or self.hosts.get("0.0.0.0")
        if not remote_host:
            logger.warning(
                "[{}:{}] Drop packet from unknown source {}", self.ip, self.port, addr
            )
            return
        secret = remote_host.secret

        try:
            logger.debug(
                "[{}:{}] Received from {} packet: {}",
                self.ip,
                self.port,
                addr,
                data.hex(),
            )
            if len(data) < 1:
                raise ServerPacketError("Packet too short to contain a code byte")
            code = data[0]
            router.reject_response_codes(code)

            # Status-Server has its own reply path: validate MA and
            # synthesize the reply without invoking the user handler.
            if code == PacketType.StatusServer:
                router.gate_code(code, self.server_type)
                self._handle_status_server(data, secret, addr)
                return

            router.gate_code(code, self.server_type)
            req = router.parse(data, secret)
            router.verify_request(req)
            router.validate_message_authenticator_policy(req)
            self.request_callback(self, req, addr)
        except Exception as exc:
            if self.server.debug:
                logger.exception(
                    "[{}:{}] Error for packet from {}", self.ip, self.port, addr
                )
            else:
                logger.error(
                    "[{}:{}] Error for packet from {}: {}",
                    self.ip,
                    self.port,
                    addr,
                    exc,
                )

        process_date = datetime.now(timezone.utc)
        elapsed = (process_date - receive_date).microseconds / 1000
        logger.debug(
            "[{}:{}] Request from {} processed in {} ms",
            self.ip,
            self.port,
            addr,
            elapsed,
        )

    def error_received(self, exc: Exception) -> None:
        logger.error("[{}:{}] Error received: {}", self.ip, self.port, exc)

    async def close_transport(self):
        if self.transport:
            logger.debug("[{}:{}] Close transport...", self.ip, self.port)
            self.transport.close()
            self.transport = None

    def __call__(self):
        return self


class ServerAsync(ABC):
    """Basic async RADIUS server.

    This class implements the basics of a RADIUS server. It takes care
    of the details of receiving and decoding requests; processing of
    the requests should be done by overloading the appropriate methods
    in derived classes.
    """

    def __init__(
        self,
        auth_port: int = 1812,
        acct_port: int = 1813,
        coa_port: int = 3799,
        hosts: Optional[Dict[str, RemoteHost]] = None,
        dictionary: Optional[Dictionary] = None,
        enable_pkt_verify: bool = True,
        debug: bool = False,
        require_message_authenticator: bool = True,
        require_eap_message_authenticator: bool = True,
        dedup_enabled: bool = True,
        dedup_ttl: float = 30.0,
        dedup_max_entries: int = 4096,
        dedup_cache: Optional[dedup.ResponseCache] = None,
    ):
        """Initialize an async server.

        Args:
            auth_port (int): Port to listen on for authentication packets.
            acct_port (int): Port to listen on for accounting packets.
            coa_port (int): Port to listen on for Dynamic Authorization packets.
            hosts (dict[str, RemoteHost]): Hosts who we can talk to. A dictionary mapping IP to RemoteHost class instances.
            dictionary (Dictionary): RADIUS dictionary to use.
            enable_pkt_verify (bool): If true, the packet will be verified
                against its secret (default: True).
            require_message_authenticator (bool): Require Message-Authenticator
                on incoming packets (default: True). Mitigates BlastRADIUS
                (CVE-2024-3596). Disable only to bridge legacy NASes that
                don't emit the attribute.
            require_eap_message_authenticator (bool): Require
                Message-Authenticator on packets containing EAP-Message.
            dedup_enabled (bool): Enable RFC 5080 duplicate detection and
                response caching (default: True).
            dedup_ttl (float): Lifetime in seconds of a cached reply.
            dedup_max_entries (int): Maximum number of cached replies before
                LRU eviction kicks in.
            dedup_cache (ResponseCache): Provide a pre-built cache to share
                between servers or to inject a custom clock for tests.
        """
        self.hosts = hosts or {}
        self.dict = dictionary
        self.enable_pkt_verify = enable_pkt_verify
        self.debug = debug
        self.require_message_authenticator = require_message_authenticator
        self.require_eap_message_authenticator = require_eap_message_authenticator
        if dedup_cache is not None:
            self._dedup_cache: Optional[dedup.ResponseCache] = dedup_cache
        elif dedup_enabled:
            self._dedup_cache = dedup.ResponseCache(
                ttl=dedup_ttl, max_entries=dedup_max_entries
            )
        else:
            self._dedup_cache = None

        self.auth_port = auth_port
        self.acct_port = acct_port
        self.coa_port = coa_port

        self.auth_protocols: list[asyncio.Protocol] = []
        self.acct_protocols: list[asyncio.Protocol] = []
        self.coa_protocols: list[asyncio.Protocol] = []

        # Shared transport-neutral dispatch helper. The sync server owns
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

    def validate_message_authenticator_policy(self, req: Packet) -> None:
        """Validate incoming Message-Authenticator policy for a request."""
        self._router.validate_message_authenticator_policy(req)

    def prepare_reply_packet(self, reply: Packet) -> None:
        """Apply outgoing Message-Authenticator policy to a reply packet."""
        self._router.force_reply_ma(reply)

    def create_status_response(
        self, pkt: StatusPacket, server_type: ServerType
    ) -> Packet:
        """Create the RFC 5997 response for a Status-Server request."""
        code = (
            PacketType.AccountingResponse
            if server_type == ServerType.Acct
            else PacketType.AccessAccept
        )
        return self.create_reply_packet(pkt, code=code)

    @staticmethod
    def _add_error_cause(reply: Packet, cause: ErrorCause) -> None:
        """Add an RFC 5176 Error-Cause value without requiring dictionary support."""
        reply[ERROR_CAUSE_ATTRIBUTE] = [int(cause).to_bytes(4, "big")]

    def _select_handler(
        self, protocol: "DatagramProtocolServer", req: Packet
    ) -> Callable[["DatagramProtocolServer", Packet, tuple[str | Any, int]], None]:
        """Map (server_type, packet code) to the user-overridable handler."""
        if protocol.server_type == ServerType.Acct:
            return self.handle_acct_packet
        if protocol.server_type == ServerType.Auth:
            return self.handle_auth_packet
        if protocol.server_type == ServerType.Coa:
            if req.code == PacketType.CoARequest:
                return self.handle_coa_packet
            if req.code == PacketType.DisconnectRequest:
                return self.handle_disconnect_packet
            raise ServerPacketError("Unexpected CoA request type")
        raise ServerPacketError(f"Unknown server type {protocol.server_type}")

    def _request_handler(
        self,
        protocol: DatagramProtocolServer,
        req: Packet,
        addr: tuple[str | Any, int],
    ):
        try:
            handler = self._select_handler(protocol, req)
            self._dedup_dispatch(protocol, req, addr, handler)
        except Exception as exc:
            msg = "[{}:{}] Unexpected error: {}".format(protocol.ip, protocol.port, exc)
            if self.debug:
                logger.exception(msg, protocol.ip, protocol.port, exc)
            else:
                logger.error(msg, protocol.ip, protocol.port, exc)

    def _dedup_dispatch(
        self,
        protocol: "DatagramProtocolServer",
        req: Packet,
        addr: tuple[str | Any, int],
        handler: Callable[["DatagramProtocolServer", Packet, tuple[str | Any, int]], None],
    ) -> None:
        """Wrap ``handler(protocol, req, addr)`` with RFC 5080 dedup."""
        key = self._router.dedup_key_for(req, source=addr)

        def _resend(raw: bytes) -> None:
            protocol.transport.sendto(raw, addr)

        action = self._router.dedup_consult(key, _resend)
        if action is dedup.DispatchAction.DROP:
            logger.debug(
                "[{}:{}] Dropping duplicate in-flight request from {}",
                protocol.ip,
                protocol.port,
                addr,
            )
            return
        if action is dedup.DispatchAction.RESENT:
            logger.debug(
                "[{}:{}] Resent cached reply for duplicate request from {}",
                protocol.ip,
                protocol.port,
                addr,
            )
            return

        if key is not None:
            req._dedup_key = key  # type: ignore[attr-defined]
        try:
            handler(protocol, req, addr)
        finally:
            self._router.dedup_drop_in_flight(key)

    async def initialize_transports(
        self,
        *,
        enable_acct: bool = False,
        enable_auth: bool = False,
        enable_coa: bool = False,
        addresses: Optional[list[str]] = None,
    ):
        if not any([enable_acct, enable_auth, enable_coa]):
            raise ValueError("No transports enabled")

        addresses = addresses or ["127.0.0.1"]
        tasks = []

        for addr in addresses:
            if enable_auth:
                tasks.append(
                    self._start_transport(
                        addr, self.auth_port, ServerType.Auth, self.auth_protocols
                    )
                )
            if enable_acct:
                tasks.append(
                    self._start_transport(
                        addr, self.acct_port, ServerType.Acct, self.acct_protocols
                    )
                )
            if enable_coa:
                tasks.append(
                    self._start_transport(
                        addr, self.coa_port, ServerType.Coa, self.coa_protocols
                    )
                )

        await asyncio.gather(*tasks)

    async def _start_transport(
        self, ip: str, port: int, server_type: ServerType, proto_list: list
    ):
        if any(proto.ip == ip for proto in proto_list):
            return
        protocol = DatagramProtocolServer(
            ip, port, self, server_type, self.hosts, self._request_handler
        )
        await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: protocol, local_addr=(ip, port), reuse_port=True
        )
        proto_list.append(protocol)

    async def deinitialize_transports(self):
        for proto_list in (
            self.auth_protocols,
            self.acct_protocols,
            self.coa_protocols,
        ):
            for proto in proto_list:
                await proto.close_transport()
            proto_list.clear()

    def create_reply_packet(self, pkt: Optional[Packet] = None, **attributes) -> Packet:
        """Create a reply packet.
        Create a new packet which can be returned as a reply to a received
        packet.

        Args:
            pkt (packet.Packet): Packet to process
            attributes (dict): Custom attributes to be added to the reply
        """
        if pkt is None:
            raise ValueError("Missing packet to reply to")
        reply = pkt.create_reply(**attributes)
        self._router.prepare_reply(pkt, reply)
        # Carry the request's dedup key forward so DatagramProtocolServer.
        # send_response can cache the encoded bytes.
        self._router.attach_dedup_key(pkt, reply)
        return reply

    @abstractmethod
    def handle_auth_packet(
        self, protocol: DatagramProtocolServer, pkt: Packet, addr: tuple[str | Any, int]
    ):
        """Authentication packet handler.
        This is an empty function that is called when a valid
        authentication packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            protocol (DatagramProtocolServer): The protocol to use when sending responses
            pkt (packet.Packet): Packet to process.
            addr (tuple): Source address and port.
        """
        pass

    @abstractmethod
    def handle_acct_packet(
        self, protocol: DatagramProtocolServer, pkt: Packet, addr: tuple[str | Any, int]
    ):
        """Accounting packet handler.
        This is an empty function that is called when a valid
        accounting packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        Args:
            protocol (DatagramProtocolServer): The protocol to use when sending responses
            pkt (packet.Packet): Packet to process.
            addr (tuple): Source address and port.
        """
        pass

    def handle_coa_packet(
        self, protocol: DatagramProtocolServer, pkt: Packet, addr: tuple[str | Any, int]
    ) -> None:
        """Handle an unsupported CoA-Request with a CoA-NAK by default.

        Subclasses that act as a Dynamic Authorization Server can override
        this method to apply authorization changes and send CoA-ACK/NAK
        responses themselves.

        Args:
            protocol (DatagramProtocolServer): The protocol to use when sending responses
            pkt (packet.Packet): Packet to process.
            addr (tuple): Source address and port.
        """
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.CoANAK
        self._add_error_cause(reply, ErrorCause.UnsupportedExtension)
        protocol.send_response(reply, addr)

    def handle_disconnect_packet(
        self, protocol: DatagramProtocolServer, pkt: Packet, addr: tuple[str | Any, int]
    ) -> None:
        """Handle an unsupported Disconnect-Request with a NAK by default.

        Subclasses that act as a Dynamic Authorization Server can override
        this method to terminate sessions and send Disconnect-ACK/NAK
        responses themselves.

        Args:
            protocol (DatagramProtocolServer): The protocol to use when sending responses
            pkt (packet.Packet): Packet to process.
            addr (tuple): Source address and port.
        """
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.DisconnectNAK
        self._add_error_cause(reply, ErrorCause.UnsupportedExtension)
        protocol.send_response(reply, addr)
