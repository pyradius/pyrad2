"""Shared dispatch state machine for UDP RADIUS servers.

``RequestRouter`` is the transport-neutral piece of ``Server`` (sync) and
``ServerAsync`` (asyncio). Both servers construct a router in their
``__init__`` and delegate per-packet policy to it so the two transports
can't drift apart:

- host lookup (`lookup_secret`),
- secret-aware decode (`parse`),
- code gating on the listening port (`gate_code`),
- per-code Request Authenticator verification (`verify_request`),
- ``Message-Authenticator`` policy (`validate_message_authenticator_policy`
  for incoming, `prepare_reply` and `force_reply_ma` for outgoing), and
- RFC 5080 dedup helpers (`dedup_*`, `record_reply`).

``ServerType`` lives here too so the sync and async servers can share the
same enum without one importing the other.

The router is intentionally a small bag of stateless-ish helpers rather
than a full request loop — the per-transport main loop (``select.poll``
vs ``asyncio.DatagramProtocol``) keeps owning I/O and handler dispatch,
which both feed packets into the same set of router methods.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable, Optional

from pyrad2 import dedup
from pyrad2 import packet as _packet
from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import ServerPacketError
from pyrad2.packet import (
    AuthPacket,
    Packet,
    PacketError,
    prepare_reply_message_authenticator,
)


class ServerType(Enum):
    """Which kind of UDP transport delivered a packet.

    Both ``server.py`` and ``server_async.py`` re-export this so user
    code can import it from either place.
    """

    Auth = "Authentication"
    Acct = "Accounting"
    Coa = "Dynamic Authorization"


_ACCESS_REPLY_CODES = frozenset(
    {PacketType.AccessAccept, PacketType.AccessReject, PacketType.AccessChallenge}
)

# Codes that should never arrive on a listening socket. Their presence
# means a remote sent us a reply meant for someone else.
_RESPONSE_CODES = frozenset(
    {
        PacketType.AccessAccept,
        PacketType.AccessReject,
        PacketType.AccountingResponse,
        PacketType.CoAACK,
        PacketType.CoANAK,
        PacketType.DisconnectACK,
        PacketType.DisconnectNAK,
    }
)


SendBytes = Callable[[bytes], None]


class RequestRouter:
    """Transport-neutral inspection, verification, MA policy, and dedup."""

    def __init__(
        self,
        *,
        hosts: dict[str, Any],
        dictionary: Optional[Dictionary],
        enable_pkt_verify: bool = True,
        require_message_authenticator: bool = True,
        require_eap_message_authenticator: bool = True,
        dedup_cache: Optional[dedup.ResponseCache] = None,
    ) -> None:
        self.hosts = hosts
        self.dictionary = dictionary
        self.enable_pkt_verify = enable_pkt_verify
        self.require_message_authenticator = require_message_authenticator
        self.require_eap_message_authenticator = require_eap_message_authenticator
        self.dedup_cache = dedup_cache

    # --- Host lookup ----------------------------------------------------
    def lookup_secret(self, addr: str) -> bytes:
        """Return the shared secret for ``addr``.

        Raises ``ServerPacketError`` if the source is not in ``hosts``
        and there's no ``"0.0.0.0"`` wildcard entry. Drops happen here
        before any attribute parsing so unknown peers can't push the
        dictionary decoder.
        """
        host = self.hosts.get(addr) or self.hosts.get("0.0.0.0")
        if host is None:
            raise ServerPacketError("Received packet from unknown host")
        return host.secret

    # --- Parse + verify -------------------------------------------------
    def parse(self, data: bytes, secret: bytes) -> Packet:
        """Decode ``data`` into the appropriate typed Packet.

        Calls ``pyrad2.packet.parse_packet`` indirectly so test fixtures
        that monkey-patch the module-level symbol still take effect.
        """
        if not data:
            raise ServerPacketError("Empty packet")
        return _packet.parse_packet(data, secret, self.dictionary)

    @staticmethod
    def reject_response_codes(code: int) -> None:
        """Reject codes that only make sense as replies, not requests."""
        if code in _RESPONSE_CODES:
            raise ServerPacketError(f"Invalid response packet {code}")

    @staticmethod
    def gate_code(code: int, server_type: ServerType) -> None:
        """Reject codes that don't belong on ``server_type``'s listener.

        Status-Server is allowed on Auth and Acct ports (per RFC 5997)
        and rejected on CoA.
        """
        if server_type == ServerType.Auth:
            if code not in (PacketType.AccessRequest, PacketType.StatusServer):
                raise ServerPacketError("Received non-auth packet on auth port")
        elif server_type == ServerType.Acct:
            if code not in (PacketType.AccountingRequest, PacketType.StatusServer):
                raise ServerPacketError(
                    "Received non-accounting packet on accounting port"
                )
        elif server_type == ServerType.Coa:
            if code == PacketType.StatusServer:
                raise ServerPacketError("Received status packet on coa port")
            if code not in (PacketType.DisconnectRequest, PacketType.CoARequest):
                raise ServerPacketError("Received non-coa packet on coa port")
        else:
            raise ServerPacketError(f"Unknown server type {server_type}")

    def verify_request(self, pkt: Any) -> None:
        """Run code-appropriate authenticator verification on ``pkt``.

        Short-circuits when ``enable_pkt_verify`` is off or ``pkt`` is
        a trivial mock (no ``Packet`` base) — both happen in unit tests.
        """
        if not self.enable_pkt_verify:
            return
        if not isinstance(pkt, Packet):
            return
        if pkt.code == PacketType.AccessRequest:
            if not isinstance(pkt, AuthPacket) or not pkt.verify_auth_request():
                raise PacketError("Packet verification failed")
        elif pkt.code in (
            PacketType.AccountingRequest,
            PacketType.CoARequest,
            PacketType.DisconnectRequest,
        ):
            if not pkt.verify_packet():
                raise PacketError("Packet verification failed")

    def validate_message_authenticator_policy(self, pkt: Any) -> None:
        """Apply BlastRADIUS / EAP / Status-Server MA rules to ``pkt``."""
        if not isinstance(pkt, Packet):
            return
        pkt.validate_message_authenticator_policy(
            require_message_authenticator=self.require_message_authenticator,
            require_eap_message_authenticator=self.require_eap_message_authenticator,
        )

    # --- Reply prep -----------------------------------------------------
    def prepare_reply(self, request: Any, reply: Any) -> None:
        """First-line MA injection at reply-construction time.

        Mirror semantics + BlastRADIUS for Access replies + EAP rule.
        See ``packet.prepare_reply_message_authenticator``.
        """
        prepare_reply_message_authenticator(
            request,
            reply,
            require_message_authenticator=self.require_message_authenticator,
            require_eap_message_authenticator=self.require_eap_message_authenticator,
        )

    def force_reply_ma(self, reply: Any) -> None:
        """Second-line MA injection at send time.

        Catches replies that bypassed ``prepare_reply`` (e.g. a handler
        built the reply by hand). Scoped to Access replies and replies
        carrying ``EAP-Message`` — body-MAC-protected codes are skipped.
        """
        if not isinstance(reply, Packet):
            return
        force_ma_for_access = (
            self.require_message_authenticator
            and reply.code in _ACCESS_REPLY_CODES
        )
        if force_ma_for_access or (
            self.require_eap_message_authenticator and reply.has_eap_message()
        ):
            reply.ensure_message_authenticator()

    # --- Dedup ----------------------------------------------------------
    def dedup_key_for(
        self, pkt: Any, source: Optional[tuple] = None
    ) -> Optional[dedup.DedupKey]:
        """Return the RFC 5080 dedup key for ``pkt`` (or ``None``)."""
        if self.dedup_cache is None:
            return None
        return dedup.key_for(pkt, source=source)

    def dedup_consult(
        self, key: Optional[dedup.DedupKey], resend: SendBytes
    ) -> dedup.DispatchAction:
        """Returns PROCESS / DROP / RESENT for the cache."""
        return dedup.consult_cache(self.dedup_cache, key, resend)

    def dedup_drop_in_flight(self, key: Optional[dedup.DedupKey]) -> None:
        """Remove the in-flight marker for ``key`` (idempotent)."""
        if key is not None and self.dedup_cache is not None:
            self.dedup_cache.drop_in_flight(key)

    def record_reply(self, reply: Any, raw: bytes) -> None:
        """Cache ``raw`` if ``reply`` carries a dedup key from its request."""
        dedup.record_if_keyed(self.dedup_cache, reply, raw)

    # --- Convenience ----------------------------------------------------
    def attach_dedup_key(self, request: Any, reply: Any) -> None:
        """Carry the request's dedup key forward onto its reply."""
        request_key = getattr(request, "_dedup_key", None)
        if request_key is not None:
            reply._dedup_key = request_key  # type: ignore[attr-defined]
