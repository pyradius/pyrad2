import asyncio
import ssl
from typing import Iterable, Optional, Sequence

from loguru import logger

from pyrad2 import eap
from pyrad2.constants import PacketType
from pyrad2.packet import (
    AcctPacket,
    AuthPacket,
    CoAPacket,
    Packet,
    PacketError,
    PacketImplementation,
    StatusPacket,
    prepare_request_message_authenticator,
)
from pyrad2.radsec.v11 import (
    NoCommonRadiusVersion,
    RadiusVersion,
    TokenCounter,
    apply_alpn,
    enforce_tls_version_floor,
    negotiate,
)
from pyrad2.tools import read_radius_packet
from pyrad2.tools import cert_fingerprint_matches, normalize_cert_fingerprint


class RadSecClient:
    # TLS 1.3 by default. RFC 9325 deprecates TLS 1.1 and below and treats
    # 1.2 as legacy; RFC 9750 mandates 1.3 for RADIUS/1.1. Set
    # ``minimum_tls_version=ssl.TLSVersion.TLSv1_2`` explicitly to bridge
    # legacy peers that can't negotiate 1.3 yet.
    DEFAULT_MINIMUM_TLS_VERSION = ssl.TLSVersion.TLSv1_3

    def __init__(
        self,
        server: str = "127.0.0.1",
        port: int = 2083,
        secret: bytes = b"radsec",
        dict=None,
        retries: int = 3,
        timeout: int = 5,
        certfile: str = "certs/client/client.cert.pem",
        keyfile: str = "certs/client/client.key.pem",
        certfile_server: str = "certs//ca/ca.cert.pem",
        check_hostname: bool = True,
        minimum_tls_version: ssl.TLSVersion = DEFAULT_MINIMUM_TLS_VERSION,
        ciphers: Optional[str] = None,
        allowed_server_fingerprints: Optional[Iterable[str]] = None,
        reuse_connection: bool = True,
        reconnect_backoff: float = 0.25,
        radius_versions: Sequence[RadiusVersion] = (RadiusVersion.V1_0,),
    ):
        """Initializes a RadSec client.

        Args:
            server (str): IP address to connect to.
            port (int): RadSec port, defaults to 2083.
            secret (bytes): Secret. Defaults to radsec as per RFC 6614.
                Different implementations support setting an arbitrary
                shared secret but if you want to stick to the RFC,
                the shared secret must be `radsec`.
            dict (Dictionary): RADIUS dictionary to use.
            certfile (str): Path to client SSL certificate
            keyfile (str): Path to client SSL certificate
            certfile_server (str): Path to server SSL certificate
            check_hostname (bool): Validate the server certificate name.
            minimum_tls_version (ssl.TLSVersion): Lowest TLS version to
                negotiate. Defaults to TLS 1.3 (RFC 9325 / RFC 9750).
                Pass ``ssl.TLSVersion.TLSv1_2`` explicitly to talk to a
                legacy server that can't yet negotiate 1.3.
            ciphers (str): Optional OpenSSL cipher string override.
            allowed_server_fingerprints (Iterable[str]): Optional SHA-256 certificate
                fingerprint allowlist for the server certificate.
            reuse_connection (bool): Reuse the TLS connection for multiple packets.
            reconnect_backoff (float): Seconds to wait before retrying after a
                connection or read failure.
            radius_versions (Sequence[RadiusVersion]): RFC 9765 protocol
                versions to advertise via ALPN. Defaults to ``(V1_0,)`` —
                identical handshake behavior to historic RadSec. Pass
                ``(V1_0, V1_1)`` to advertise both; the server picks the
                highest mutually supported version. **Experimental.**

        """
        self.server = server
        self.port = port
        self.secret = secret
        self.retries = retries
        self.timeout = timeout
        self.dict = dict
        self.reuse_connection = reuse_connection
        self.reconnect_backoff = reconnect_backoff
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._io_lock = asyncio.Lock()

        self.allowed_server_fingerprints = {
            normalize_cert_fingerprint(fingerprint)
            for fingerprint in (allowed_server_fingerprints or [])
        }
        self.radius_versions: tuple[RadiusVersion, ...] = tuple(radius_versions)
        if not self.radius_versions:
            raise ValueError("radius_versions must contain at least one entry")
        # RFC 9765 §3.4: RADIUS/1.1 requires TLS 1.3+. Auto-promote the
        # configured floor when v1.1 is advertised.
        minimum_tls_version = enforce_tls_version_floor(
            minimum_tls_version, self.radius_versions
        )
        # Negotiated post-handshake. _token_counter is only meaningful for v1.1.
        self._negotiated_version: RadiusVersion = RadiusVersion.V1_0
        self._token_counter: TokenCounter | None = None
        # Last fatal error from send_packet, exposed so callers can tell a
        # strict-mode negotiation refusal apart from a normal timeout/no-reply
        # (both currently surface as ``send_packet`` returning ``None``).
        # Cleared at the start of each send_packet call.
        self.last_error: Exception | None = None

        self.setup_ssl(
            certfile,
            keyfile,
            certfile_server,
            check_hostname,
            minimum_tls_version,
            ciphers,
        )

    def setup_ssl(
        self,
        certfile: str,
        keyfile: str,
        certfile_server: str,
        check_hostname: bool,
        minimum_tls_version: ssl.TLSVersion,
        ciphers: Optional[str],
    ):
        try:
            self.ssl_ctx = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cafile=certfile_server
            )

            self.ssl_ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        except FileNotFoundError as e:
            ssl_paths = ", ".join([certfile, keyfile, certfile_server])
            msg = "One or more SSL files could not be found. Current paths: {}"
            logger.error(msg, ssl_paths)
            raise FileNotFoundError(msg.format(ssl_paths)) from e

        self.ssl_ctx.check_hostname = check_hostname
        self.ssl_ctx.minimum_version = minimum_tls_version
        if ciphers is not None:
            self.ssl_ctx.set_ciphers(ciphers)

        # RFC 9765 §3.1: advertise the configured RADIUS protocol versions.
        # No-op when only V1_0 is configured.
        apply_alpn(self.ssl_ctx, self.radius_versions)

    def _verify_server_fingerprint(self, writer: asyncio.StreamWriter) -> bool:
        """Verify the connected server certificate against the fingerprint allowlist.

        If no fingerprints were configured, the certificate trust decision is
        left to Python's TLS verification.
        """
        if not self.allowed_server_fingerprints:
            return True

        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return False

        cert = ssl_object.getpeercert(binary_form=True)
        if cert is None:
            return False

        return cert_fingerprint_matches(cert, self.allowed_server_fingerprints)

    @staticmethod
    def _writer_is_closing(writer: asyncio.StreamWriter | None) -> bool:
        """Return whether a stream writer is absent or already closing."""
        if writer is None:
            return True
        is_closing = getattr(writer, "is_closing", None)
        if is_closing is None:
            return False
        return is_closing()

    async def _close_writer(self, writer: asyncio.StreamWriter | None) -> None:
        """Close a stream writer and wait until the close completes."""
        if writer is None:
            return
        writer.close()
        await writer.wait_closed()

    async def close(self) -> None:
        """Close any reusable RadSec connection held by the client."""
        writer = self._writer
        self._reader = None
        self._writer = None
        # Negotiated version + Token counter are per-connection; clear them.
        self._negotiated_version = RadiusVersion.V1_0
        self._token_counter = None
        await self._close_writer(writer)

    async def __aenter__(self) -> "RadSecClient":
        """Return this client for use as an async context manager."""
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """Close the reusable RadSec connection when leaving a context manager."""
        await self.close()

    async def _open_connection(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open and validate a TLS connection to the RadSec server."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.server, self.port, ssl=self.ssl_ctx),
            timeout=self.timeout,
        )

        ssl_object = writer.get_extra_info("ssl_object")
        selected_alpn = (
            ssl_object.selected_alpn_protocol() if ssl_object is not None else None
        )
        try:
            self._negotiated_version = negotiate(self.radius_versions, selected_alpn)
        except NoCommonRadiusVersion as exc:
            # RFC 9765 §3.3: a strict-mode client (no v1.0 in
            # radius_versions) must not silently downgrade. Close the
            # half-open connection and surface a clean failure.
            await self._close_writer(writer)
            raise PacketError(
                "No common RADIUS protocol version with RadSec server: " + str(exc)
            ) from exc
        self._token_counter = (
            TokenCounter()
            if self._negotiated_version == RadiusVersion.V1_1
            else None
        )

        logger.info(
            "Connected to RADSEC server on {}:{} (ALPN={}, RADIUS/{})",
            self.server,
            self.port,
            selected_alpn or "none",
            "1.1" if self._negotiated_version == RadiusVersion.V1_1 else "1.0",
        )

        if not self._verify_server_fingerprint(writer):
            await self._close_writer(writer)
            raise PacketError("Server certificate fingerprint is not allowed")

        return reader, writer

    async def _ensure_connection(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Return an existing reusable connection or open a new one."""
        if (
            self.reuse_connection
            and self._reader is not None
            and not self._writer_is_closing(self._writer)
        ):
            assert self._writer is not None
            return self._reader, self._writer

        await self.close()
        self._reader, self._writer = await self._open_connection()
        return self._reader, self._writer

    async def _write_packet(
        self, writer: asyncio.StreamWriter, packet: PacketImplementation
    ) -> None:
        """Write one RADIUS packet to the RadSec stream within the client timeout."""
        self._stamp_radius_version(packet)
        self._prepare_outgoing_packet(packet)
        writer.write(packet.request_packet())
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)

    def _stamp_radius_version(self, packet: PacketImplementation) -> None:
        """Tag an outgoing packet with the negotiated RADIUS version.

        Always overwrites ``packet.radius_version`` so a packet that was
        previously serialized under a different negotiated version (for
        example after a reconnect that dropped from v1.1 back to v1.0)
        gets re-serialized correctly on retry rather than carrying its
        prior v1.1 state — Token, zero Identifier, plaintext password —
        onto a v1.0 wire format.

        For v1.1 we also stamp a fresh Token — done exactly once per
        packet so a retry reuses the same Token (hitting the server's
        RFC 5080 dedup cache). The Token lives in its own slot,
        distinct from ``packet.authenticator``, so any prior v1.0 flow
        that populated authenticator (e.g. pw_crypt) can't leak random
        bytes into the v1.1 Reserved-2 region (RFC 9765 §4.1).
        """
        packet.radius_version = self._negotiated_version
        if self._negotiated_version == RadiusVersion.V1_1:
            if packet.token is None and self._token_counter is not None:
                packet.token = self._token_counter.next()
        else:
            # Clear any leftover v1.1 Token so the v1.0 serializer doesn't
            # see it; the v1.0 path computes its own authenticator anyway,
            # so the Token slot has no meaning here.
            packet.token = None

    def _prepare_outgoing_packet(self, packet: PacketImplementation) -> None:
        """Apply Message-Authenticator policy before a packet is sent."""
        prepare_request_message_authenticator(packet)

    async def _read_packet(self, reader: asyncio.StreamReader) -> bytes:
        """Read one RADIUS packet from the RadSec stream within the client timeout."""
        return await asyncio.wait_for(read_radius_packet(reader), timeout=self.timeout)

    async def _send_packet_once(self, packet: PacketImplementation) -> Optional[Packet]:
        """Send one RADIUS packet over the current connection strategy."""
        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter | None = None

        if self.reuse_connection:
            reader, writer = await self._ensure_connection()
        else:
            reader, writer = await self._open_connection()

        try:
            await self._write_packet(writer, packet)
            response = await self._read_packet(reader)

            logger.info("Received {} bytes from server", len(response))
            logger.debug("Response: {}", response.hex())

            reply = packet.create_reply(packet=response)
            if packet.verify_reply(reply, response):
                return reply

            raise PacketError("Received invalid RADSEC reply")
        finally:
            if not self.reuse_connection:
                await self._close_writer(writer)

    def create_auth_packet(self, **kwargs) -> AuthPacket:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            Packet: A new AuthPacket instance
        """
        id = kwargs.pop("id", Packet.create_id())
        return AuthPacket(
            dict=self.dict,
            id=id,
            secret=self.secret,
            **kwargs,
        )

    def create_acct_packet(self, **kwargs) -> AcctPacket:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            Packet: A new AcctPacket instance
        """
        id = kwargs.pop("id", Packet.create_id())
        return AcctPacket(
            id=id,
            dict=self.dict,
            secret=self.secret,
            **kwargs,
        )

    def create_coa_packet(self, **kwargs) -> CoAPacket:
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        Returns:
            Packet: A new CoA packet instance
        """
        id = kwargs.pop("id", Packet.create_id())
        return CoAPacket(id=id, dict=self.dict, secret=self.secret, **kwargs)

    def create_status_packet(self, **kwargs) -> StatusPacket:
        """Create an RFC 5997 Status-Server health-check packet."""
        id = kwargs.pop("id", Packet.create_id())
        return StatusPacket(id=id, dict=self.dict, secret=self.secret, **kwargs)

    def create_packet(self, id, **kwargs) -> Packet:
        """Create a generic RADIUS packet with this client's dictionary and secret."""
        return Packet(id=id, dict=self.dict, secret=self.secret, **kwargs)

    async def _send_packet(self, packet: PacketImplementation) -> Optional[Packet]:
        """Send a packet to a RadSec server with timeout and reconnect handling.

        Args:
            packet (Packet): The packet to send
        """
        self.last_error = None
        attempts = max(1, self.retries)
        retryable_errors = (
            asyncio.IncompleteReadError,
            asyncio.TimeoutError,
            ConnectionError,
            EOFError,
            OSError,
        )

        async with self._io_lock:
            for attempt in range(attempts):
                try:
                    return await self._send_packet_once(packet)
                except PacketError as exc:
                    # Most PacketErrors here are non-retryable handshake-level
                    # failures: ALPN refused downgrade, certificate fingerprint
                    # mismatch, or a malformed server reply. Stash the cause
                    # so callers can distinguish them from "no reply received"
                    # (which leaves last_error as None).
                    self.last_error = exc
                    tag = (
                        "RADSEC negotiation failure"
                        if "No common RADIUS protocol" in str(exc)
                        else "RADSEC packet error"
                    )
                    logger.error("{}: {}", tag, exc)
                    await self.close()
                    return None
                except retryable_errors as exc:
                    self.last_error = exc
                    logger.warning(
                        "RADSEC request attempt {}/{} failed: {}",
                        attempt + 1,
                        attempts,
                        exc,
                    )
                    await self.close()

                if attempt + 1 < attempts and self.reconnect_backoff > 0:
                    await asyncio.sleep(self.reconnect_backoff)

        return None

    async def send_packet(self, packet: PacketImplementation) -> Optional[Packet]:
        """Send a packet to a RADIUS server.

        Args:
            packet (Packet): The packet to send
        """
        if isinstance(packet, AuthPacket):
            if packet.auth_type == "eap-md5":
                eap.inject_eap_identity(packet)
            reply = await self._send_packet(packet)
            if (
                reply
                and reply.code == PacketType.AccessChallenge
                and packet.auth_type == "eap-md5"
            ):
                eap.apply_eap_md5_challenge(packet, reply)
                reply = await self._send_packet(packet)
            return reply
        elif isinstance(packet, CoAPacket):
            return await self._send_packet(packet)
        else:
            return await self._send_packet(packet)
