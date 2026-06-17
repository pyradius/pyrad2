__docformat__ = "epytext en"

import asyncio
import random
from datetime import datetime
from typing import Optional, cast

from loguru import logger

from pyrad2 import eap
from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import IdentifierExhausted
from pyrad2.host import _ClientPacketFactoryMixin
from pyrad2.packet import (
    AcctPacket,
    AuthPacket,
    CoAPacket,
    Packet,
    PacketImplementation,
    StatusPacket,
    prepare_request_message_authenticator,
)
from pyrad2.retry import RetryPolicy, _LegacyAttrMixin, policy_from_legacy


class DatagramProtocolClient(_LegacyAttrMixin, asyncio.Protocol):
    def __init__(
        self,
        server: str,
        port: int,
        client: "ClientAsync",
        retries: int = 3,
        timeout: int = 30,
        retry_policy: Optional[RetryPolicy] = None,
    ):
        self.port = port
        self.server = server
        # ``retries`` / ``timeout`` attribute access proxies through
        # ``_LegacyAttrMixin``.
        self.retry_policy = policy_from_legacy(retry_policy, retries, timeout)
        self.client = client

        # Map of pending requests
        self.pending_requests: dict[int, dict] = {}

        # Use cryptographic-safe random generator as provided by the OS.
        random_generator = random.SystemRandom()
        self.packet_id = random_generator.randrange(0, 256)

        self.timeout_future = None

    async def __timeout_handler__(self):
        """Background task that retries or fails timed-out pending requests.

        Runs once per `next_wake_up` seconds. For each pending request we
        compare elapsed time against `self.timeout`; if elapsed has expired,
        we either resend the packet (consuming one retry) or surface a
        TimeoutError on the request's future. `next_wake_up` is the minimum
        remaining-time-to-timeout across all pending requests, so the loop
        wakes exactly when the next request needs servicing.
        """
        try:
            while True:
                req2delete = []
                now = datetime.now()
                # Heartbeat: the bound that applies when no pending
                # request is closer than the base timeout. Falling back
                # to ``max_wait`` here would make an idle handler nap up
                # to 30s and miss freshly-enqueued requests.
                next_wake_up = float(self.retry_policy.timeout)

                for id, req in self.pending_requests.items():
                    # send_date is always <= now, so compute elapsed as a
                    # positive float. Using timedelta.seconds here would
                    # wrap negative deltas to ~86399 and prematurely
                    # trigger the timeout branch.
                    elapsed = (now - req["send_date"]).total_seconds()
                    # ``current_wait`` is the policy's wait for the
                    # attempt currently in flight — retry N timed out
                    # after ``wait_for(N)`` seconds.
                    current_wait = self.retry_policy.wait_for(req["retries"])
                    if elapsed >= current_wait:
                        if req["retries"] >= self.retry_policy.retries:
                            logger.debug(
                                "[{}:{}] For request {} execute all retries",
                                self.server,
                                self.port,
                                id,
                            )
                            req["future"].set_exception(
                                TimeoutError("Timeout on Reply")
                            )
                            req2delete.append(id)
                        else:
                            # Send again packet
                            req["send_date"] = now
                            req["retries"] += 1
                            logger.debug(
                                "[{}:{}] For request {} execute retry {}",
                                self.server,
                                self.port,
                                id,
                                req["retries"],
                            )
                            self.transport.sendto(req["packet"].request_packet())
                    else:
                        remaining = current_wait - elapsed
                        if remaining < next_wake_up:
                            next_wake_up = remaining

                for id in req2delete:
                    # Remove request for map
                    del self.pending_requests[id]

                # Floor sleeps at 0 so a just-expired request gets serviced
                # on the next loop iteration instead of busy-spinning.
                await asyncio.sleep(max(0.0, next_wake_up))

        except asyncio.CancelledError:
            pass

    def send_packet(self, packet: PacketImplementation, future: asyncio.Future):
        if packet.id in self.pending_requests:
            raise IdentifierExhausted("Packet with id %d already in flight" % packet.id)

        # Store packet on pending requests map
        self.pending_requests[packet.id] = {
            "packet": packet,
            "creation_date": datetime.now(),
            "retries": 0,
            "future": future,
            "send_date": datetime.now(),
        }

        # In queue packet raw on socket buffer
        self.transport.sendto(packet.request_packet())

    def connection_made(self, transport: asyncio.BaseTransport):
        # Duck-typed instead of ``isinstance(transport, asyncio.DatagramTransport)``
        # so the client works under non-asyncio loops (uvloop's UDPTransport
        # implements the protocol structurally but is not a subclass).
        if not hasattr(transport, "sendto"):
            raise TypeError(
                f"Expected a DatagramTransport-like object, got {type(transport).__name__}"
            )
        self.transport: asyncio.DatagramTransport = cast(
            asyncio.DatagramTransport, transport
        )

        socket = transport.get_extra_info("socket")
        logger.info(
            "[{}:{}] Transport created with binding in {}:{}",
            self.server,
            self.port,
            socket.getsockname()[0],
            socket.getsockname()[1],
        )

        # Start asynchronous timer handler
        self.timeout_future = asyncio.ensure_future(self.__timeout_handler__())

    def error_received(self, exc: Exception) -> None:
        logger.error("[{}:{}] Error received: {}", self.server, self.port, exc)

    def connection_lost(self, exc) -> None:
        if exc:
            logger.warning(
                "[{}:{}] Connection lost: {}", self.server, self.port, str(exc)
            )
        else:
            logger.info("[{}:{}] Transport closed", self.server, self.port)

    def datagram_received(self, data: bytes, addr: str):
        try:
            reply = Packet(packet=data, dict=self.client.dict)

            if reply.code and reply.id in self.pending_requests:
                req = self.pending_requests[reply.id]
                packet = req["packet"]

                reply.dict = packet.dict
                reply.secret = packet.secret

                if packet.verify_reply(reply, data, enforce_ma=self.client.enforce_ma):
                    req["future"].set_result(reply)
                    # Remove request for map
                    del self.pending_requests[reply.id]
                else:
                    logger.warning(
                        "[{}:{}] Ignore invalid reply for id {}: {}",
                        self.server,
                        self.port,
                        reply.id,
                        data,
                    )
            else:
                logger.warning(
                    "[{}:{}] Ignore invalid reply: {}", self.server, self.port, data
                )

        except Exception as exc:
            logger.error(
                "[{}:{}] Error on decode packet: {}", self.server, self.port, exc
            )

    async def close_transport(self) -> None:
        if self.transport:
            logger.debug("[{}:{}] Closing transport...", self.server, self.port)
            self.transport.close()
            self.transport = None  # type: ignore
        if self.timeout_future:
            self.timeout_future.cancel()
            await self.timeout_future
            self.timeout_future = None

    def create_id(self) -> int:
        """Return the next free RADIUS Identifier for this transport.

        Scans forward from the last-used id looking for a slot that
        isn't already in ``pending_requests``. Raises
        ``IdentifierExhausted`` if all 256 slots are pending — RFC 2865
        §3 caps the field at one octet, so a single (source IP, port)
        flow can't carry more than 256 simultaneous outstanding
        requests. Callers that hit this should wait for an in-flight
        request to complete, open a second transport for more capacity,
        or queue.
        """
        start = self.packet_id
        for offset in range(1, 257):
            candidate = (start + offset) % 256
            if candidate not in self.pending_requests:
                self.packet_id = candidate
                return candidate
        raise IdentifierExhausted(
            "All 256 RADIUS Identifier slots are in flight on this transport"
        )

    def __str__(self) -> str:
        return "DatagramProtocolClient(server?=%s, port=%d)" % (self.server, self.port)

    # Used as protocol_factory
    def __call__(self):
        return self


class ClientAsync(_ClientPacketFactoryMixin, _LegacyAttrMixin):
    """Asyncio-based RADIUS client.

    Sends Access-Request, Accounting-Request, CoA, and Status-Server
    packets over UDP, validates replies (including
    ``Message-Authenticator`` when present), and retries timed-out
    requests up to ``retries`` times with a per-request budget of
    ``timeout`` seconds.

    EAP-MD5 is handled transparently: setting ``auth_type="eap-md5"``
    on the request makes ``send_packet`` perform the EAP-Identity /
    Access-Challenge / EAP-MD5-Response round-trip and return only
    the final reply.
    """

    def __init__(
        self,
        server: str,
        auth_port: int = 1812,
        acct_port: int = 1813,
        coa_port: int = 3799,
        secret: bytes = b"",
        dict: Optional[Dictionary] = None,
        retries: int = 3,
        timeout: int = 30,
        enforce_ma: bool = True,
        retry_policy: Optional[RetryPolicy] = None,
    ):
        """Initializes an async RADIUS client.

        Args:
            server (str): Hostname or IP address of the RADIUS server.
            auth_port (int): Port to use for authentication packets.
            acct_port (int): Port to use for accounting packets.
            coa_port (int): Port to use for CoA packets.
            secret (bytes): RADIUS secret.
            dict (pyrad.dictionary.Dictionary): RADIUS dictionary.
            retries (int): Number of retransmissions before giving up.
                Ignored when ``retry_policy`` is supplied.
            timeout (int): Base seconds to wait for a reply. Ignored
                when ``retry_policy`` is supplied.
            enforce_ma (bool): Enforce Message-Authenticator on requests
                and replies (default: True). Mitigates BlastRADIUS
                (CVE-2024-3596). Disable only when talking to a legacy
                server that can't process the attribute.
            retry_policy (RetryPolicy): Optional explicit policy adding
                exponential backoff and jitter on top of the base
                ``timeout``. When omitted, a flat policy is built from
                ``retries`` and ``timeout`` for backwards compatibility.
        """
        self.server = server
        self.secret = secret
        # ``retries`` / ``timeout`` attribute access proxies through
        # ``_LegacyAttrMixin``.
        self.retry_policy = policy_from_legacy(retry_policy, retries, timeout)
        self.dict = dict
        self.enforce_ma = enforce_ma

        self.auth_port = auth_port
        self.protocol_auth: Optional[DatagramProtocolClient] = None

        self.acct_port = acct_port
        self.protocol_acct: Optional[DatagramProtocolClient] = None

        self.protocol_coa: Optional[DatagramProtocolClient] = None
        self.coa_port = coa_port

    def _prepare_outgoing_packet(self, pkt: Packet) -> None:
        """Apply Message-Authenticator policy before a packet is sent."""
        prepare_request_message_authenticator(
            pkt,
            require_message_authenticator=self.enforce_ma,
        )

    async def initialize_transports(
        self,
        enable_acct: bool = False,
        enable_auth: bool = False,
        enable_coa: bool = False,
        local_addr: Optional[str] = None,
        local_auth_port: Optional[int] = None,
        local_acct_port: Optional[int] = None,
        local_coa_port: Optional[int] = None,
    ):
        task_list = []

        if not enable_acct and not enable_auth and not enable_coa:
            raise Exception("No transports selected")

        loop = asyncio.get_running_loop()
        if enable_acct and not self.protocol_acct:
            self.protocol_acct = DatagramProtocolClient(
                self.server,
                self.acct_port,
                self,
                retry_policy=self.retry_policy,
            )
            bind_addr = None
            if local_addr and local_acct_port:
                bind_addr = (local_addr, local_acct_port)

            acct_connect = loop.create_datagram_endpoint(
                self.protocol_acct,
                reuse_port=True,
                remote_addr=(self.server, self.acct_port),
                local_addr=bind_addr,
            )
            task_list.append(acct_connect)

        if enable_auth and not self.protocol_auth:
            self.protocol_auth = DatagramProtocolClient(
                self.server,
                self.auth_port,
                self,
                retry_policy=self.retry_policy,
            )
            bind_addr = None
            if local_addr and local_auth_port:
                bind_addr = (local_addr, local_auth_port)

            auth_connect = loop.create_datagram_endpoint(
                self.protocol_auth,
                reuse_port=True,
                remote_addr=(self.server, self.auth_port),
                local_addr=bind_addr,
            )
            task_list.append(auth_connect)

        if enable_coa and not self.protocol_coa:
            self.protocol_coa = DatagramProtocolClient(
                self.server,
                self.coa_port,
                self,
                retry_policy=self.retry_policy,
            )
            bind_addr = None
            if local_addr and local_coa_port:
                bind_addr = (local_addr, local_coa_port)

            coa_connect = loop.create_datagram_endpoint(
                self.protocol_coa,
                reuse_port=True,
                remote_addr=(self.server, self.coa_port),
                local_addr=bind_addr,
            )
            task_list.append(coa_connect)

        await asyncio.gather(*task_list, return_exceptions=False)

    async def deinitialize_transports(
        self,
        deinit_coa: bool = True,
        deinit_auth: bool = True,
        deinit_acct: bool = True,
    ) -> None:
        if self.protocol_coa and deinit_coa:
            await self.protocol_coa.close_transport()
            del self.protocol_coa
            self.protocol_coa = None
        if self.protocol_auth and deinit_auth:
            await self.protocol_auth.close_transport()
            del self.protocol_auth
            self.protocol_auth = None
        if self.protocol_acct and deinit_acct:
            await self.protocol_acct.close_transport()
            del self.protocol_acct
            self.protocol_acct = None

    def _protocol_for_server_type(self, server_type: str) -> DatagramProtocolClient:
        """Look up the initialised ``DatagramProtocolClient`` for a server type.

        Raises ``Exception`` if the matching transport hasn't been started
        yet — callers of ``create_*_packet`` need the id space to come
        from the same socket the packet will eventually be sent on.
        """
        if server_type == self._AUTH_SERVER_TYPE:
            if not self.protocol_auth:
                raise Exception("Transport not initialized")
            return self.protocol_auth
        if server_type == self._ACCT_SERVER_TYPE:
            if not self.protocol_acct:
                raise Exception("Transport not initialized")
            return self.protocol_acct
        if server_type == self._COA_SERVER_TYPE:
            if not self.protocol_coa:
                raise Exception("Transport not initialized")
            return self.protocol_coa
        raise ValueError(f"Unknown server type {server_type!r}")

    def _allocate_packet_id(self, server_type: str) -> int:
        """Pull the next free identifier from the matching transport's
        per-flow counter. See ``DatagramProtocolClient.create_id``."""
        return self._protocol_for_server_type(server_type).create_id()

    def _status_protocol(self, port: str) -> DatagramProtocolClient:
        """Return the protocol used for a Status-Server health check."""
        if port == "auth":
            if not self.protocol_auth:
                raise Exception("Auth transport not initialized")
            return self.protocol_auth
        if port == "acct":
            if not self.protocol_acct:
                raise Exception("Accounting transport not initialized")
            return self.protocol_acct
        raise ValueError("Status-Server port must be 'auth' or 'acct'")

    def create_status_packet(self, *, port: str = "auth", **args) -> StatusPacket:
        """Create an RFC 5997 Status-Server health-check packet.

        Overrides the mixin to honour the ``port`` kwarg, since async
        Status-Server probes can be routed at either the auth or
        accounting transport's id space.
        """
        protocol = self._status_protocol(port)
        return StatusPacket(
            id=protocol.create_id(),
            dict=self.dict,
            secret=self.secret,
            **args,
        )

    def create_packet(self, id: int, **args) -> Packet:
        if not id:
            raise Exception("Missing mandatory packet id")

        return Packet(id=id, dict=self.dict, secret=self.secret, **args)

    def send_status_packet(
        self, pkt: Optional[StatusPacket] = None, *, port: str = "auth"
    ) -> asyncio.Future:
        """Send a Status-Server packet to the auth or accounting port."""
        protocol = self._status_protocol(port)
        if pkt is None:
            pkt = self.create_status_packet(port=port)

        ans: asyncio.Future = asyncio.get_running_loop().create_future()
        self._prepare_outgoing_packet(pkt)
        protocol.send_packet(pkt, ans)
        return ans

    def send_packet(self, pkt: Packet) -> asyncio.Future:
        """Send a packet to a RADIUS server.

        Handles EAP-MD5 challenge/response automatically when
        ``pkt.auth_type == "eap-md5"``: an EAP-Identity is injected
        before the first send, and an Access-Challenge reply triggers
        a transparent second exchange that carries the MD5 response
        back to the server. The returned Future resolves with the
        final reply (Access-Accept or Access-Reject) or rejects with
        ``TimeoutError`` if retries are exhausted.

        Args:
            pkt (Packet): The packet to send

        Returns:
            asyncio.Future: Future related with packet to send
        """

        if isinstance(pkt, StatusPacket):
            return self.send_status_packet(pkt)

        if isinstance(pkt, AuthPacket):
            if not self.protocol_auth:
                raise Exception("Transport not initialized")
            return self._send_auth_packet(pkt)

        ans: asyncio.Future = asyncio.get_running_loop().create_future()
        self._prepare_outgoing_packet(pkt)

        if isinstance(pkt, AcctPacket):
            if not self.protocol_acct:
                raise Exception("Transport not initialized")

            self.protocol_acct.send_packet(pkt, ans)

        elif isinstance(pkt, CoAPacket):
            if not self.protocol_coa:
                raise Exception("Transport not initialized")

            self.protocol_coa.send_packet(pkt, ans)

        else:
            raise Exception("Unsupported packet")

        return ans

    def _send_auth_packet(self, pkt: AuthPacket) -> asyncio.Future:
        """Send an Access-Request, driving an EAP exchange if registered.

        When ``pkt.auth_type`` matches a method in the EAP registry the
        loop calls ``method.start`` once before the first send and
        ``method.respond`` after every ``Access-Challenge`` reply,
        continuing until the server returns ``Access-Accept`` /
        ``Access-Reject``. Between rounds the packet's id and
        authenticator are regenerated so the transport's per-id pending
        map stays consistent.

        Returns an ``asyncio.Future`` that resolves with the final
        reply or rejects with whatever exception the transport / method
        surfaced.
        """
        assert self.protocol_auth is not None
        # Capture the protocol locally so the nested callbacks use it
        # without re-asserting (mypy cannot prove self.protocol_auth is
        # still non-None when each callback fires).
        protocol = self.protocol_auth

        method = eap.get_method(pkt.auth_type)
        if method is not None:
            method.start(pkt)

        loop = asyncio.get_running_loop()
        outer: asyncio.Future = loop.create_future()
        self._prepare_outgoing_packet(pkt)

        def _send_round() -> None:
            """Queue ``pkt`` on the transport and route the reply back."""
            fut: asyncio.Future = loop.create_future()
            protocol.send_packet(pkt, fut)
            fut.add_done_callback(_on_reply)

        def _on_reply(fut: asyncio.Future) -> None:
            if outer.done():
                return
            if fut.cancelled():
                outer.cancel()
                return
            exc = fut.exception()
            if exc is not None:
                outer.set_exception(exc)
                return

            reply = fut.result()
            if (
                method is not None
                and reply is not None
                and reply.code == PacketType.AccessChallenge
            ):
                try:
                    method.respond(pkt, reply)
                except Exception as challenge_exc:  # noqa: BLE001
                    outer.set_exception(challenge_exc)
                    return
                # Each retry reuses the same Packet object, so it needs
                # a fresh id/authenticator before re-entering the
                # transport — the pending-request map is keyed by id.
                pkt.id = protocol.create_id()
                pkt.authenticator = pkt.create_authenticator()
                self._prepare_outgoing_packet(pkt)
                _send_round()
                return

            outer.set_result(reply)

        _send_round()
        return outer
