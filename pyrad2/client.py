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


class Client(host._ClientPacketFactoryMixin, host.Host):
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
        # Only the address family matters here; pass ``port=None`` so we
        # don't bother resolving any service entry, and ``type=SOCK_DGRAM``
        # so the result is filtered to UDP (RADIUS). The broad except
        # preserves the legacy "fall back to IPv4 on anything weird"
        # behaviour — including when callers pass a non-string sentinel
        # in tests; the eventual bind/sendto will surface a real error.
        try:
            family = socket.getaddrinfo(self.server, None, type=socket.SOCK_DGRAM)[0][0]
        except Exception:  # noqa: BLE001 — see comment above
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

    # ``create_*_packet`` is provided by ``_ClientPacketFactoryMixin``
    # via the MRO. Sync ``Client`` defers ``id`` allocation to the
    # ``Packet`` constructor's module-level counter (no per-transport
    # tracking — the sync client serialises sends so internal id
    # collisions can't happen).

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

        # ``Acct-Delay-Time`` is bumped per retry to reflect how long the
        # request has been in flight. Snapshot the caller's original
        # value (or note its absence) so the increment doesn't accumulate
        # into the caller's packet across successive ``send_packet``
        # invocations on the same object. ``getattr`` because some test
        # paths pass ``pkt=None`` to exercise the no-retries timeout.
        is_acct = getattr(pkt, "code", None) == PacketType.AccountingRequest
        original_acct_delay: Optional[list] = None
        had_acct_delay = False
        if is_acct:
            had_acct_delay = "Acct-Delay-Time" in pkt
            if had_acct_delay:
                # Preserve the full list (RADIUS attributes are sequences)
                # so multi-valued or tagged Acct-Delay-Time round-trips
                # exactly.
                original_acct_delay = list(pkt["Acct-Delay-Time"])

        try:
            for attempt in range(self.retries):
                if attempt and is_acct:
                    if "Acct-Delay-Time" in pkt:
                        pkt["Acct-Delay-Time"] = (
                            pkt["Acct-Delay-Time"][0] + self.timeout
                        )
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
                        if pkt.verify_reply(
                            reply, rawreply, enforce_ma=self.enforce_ma
                        ):
                            if hasattr(pkt, "authenticator"):
                                reply.request_authenticator = pkt.authenticator

                            return reply
                    except packet.PacketError:
                        pass

                    now = time.time()

            raise Timeout
        finally:
            if is_acct:
                if had_acct_delay:
                    pkt["Acct-Delay-Time"] = original_acct_delay  # type: ignore[assignment]
                elif "Acct-Delay-Time" in pkt:
                    # We synthesised it during the retries — drop it so
                    # the caller's packet returns to its original shape.
                    del pkt["Acct-Delay-Time"]

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
