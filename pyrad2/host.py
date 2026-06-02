import socket
from typing import Any, Optional

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


class _ClientPacketFactoryMixin:
    """Shared ``create_*_packet`` wrappers for the three client classes.

    ``Client`` (sync, in ``pyrad2/client.py``), ``ClientAsync`` (asyncio,
    in ``pyrad2/client_async.py``), and ``RadSecClient`` (in
    ``pyrad2/radsec/client.py``) all need to construct outgoing packets
    pre-populated with their ``dict`` and ``secret``. The three used to
    each define their own four near-identical wrappers; this mixin
    collapses that into one.

    Subclasses customise:

    * ``_allocate_packet_id`` — return an explicit id (e.g. a per-transport
      counter) or ``None`` to defer to the ``Packet`` constructor's
      global counter.
    * ``_client_enforces_message_authenticator`` — whether outgoing
      Access-Requests are stamped with ``Message-Authenticator`` at
      construction. Defaults to ``self.enforce_ma`` when present and
      ``False`` otherwise (``RadSecClient`` doesn't define ``enforce_ma``
      because TLS already authenticates the bytes).

    Subclasses that need to take extra arguments — e.g. ``ClientAsync``'s
    ``port="auth"`` on ``create_status_packet`` — override the specific
    factory method instead of the helper.
    """

    # Declared for mypy so subclass attribute access type-checks. Subclasses
    # set these in ``__init__``; the mixin treats them as read-only.
    secret: bytes
    dict: Optional[Dictionary]

    # Server-type labels passed through to ``_allocate_packet_id`` so a
    # subclass can pick the right id space when it manages a counter
    # per transport. Defined as class attributes so a subclass can
    # rename them if it ever needs to.
    _AUTH_SERVER_TYPE = "auth"
    _ACCT_SERVER_TYPE = "acct"
    _COA_SERVER_TYPE = "coa"
    _STATUS_SERVER_TYPE = "auth"

    def _allocate_packet_id(self, server_type: str) -> Optional[int]:
        """Return the id to inject, or ``None`` to defer to ``Packet``'s
        module-level counter. Override on async / RadSec to provide a
        per-transport identifier."""
        return None

    def _client_enforces_message_authenticator(self) -> bool:
        """Whether outgoing Access-Requests should be stamped with
        ``Message-Authenticator`` at construction. The historic behaviour
        is to follow ``enforce_ma`` when the attribute exists, which the
        BlastRADIUS-default ``True`` flow on UDP clients flips on.
        ``RadSecClient`` doesn't define ``enforce_ma`` so this falls back
        to ``False`` there (TLS authenticates the bytes)."""
        return bool(getattr(self, "enforce_ma", False))

    def _build_packet(
        self,
        cls: type,
        server_type: str,
        *,
        inject_ma: bool = False,
        **kwargs: Any,
    ):
        """Construct ``cls`` with ``dict`` and ``secret`` from ``self`` and
        an optional ``id`` from ``_allocate_packet_id``."""
        kwargs.setdefault("secret", self.secret)
        kwargs.setdefault("dict", self.dict)
        if "id" not in kwargs:
            pkt_id = self._allocate_packet_id(server_type)
            if pkt_id is not None:
                kwargs["id"] = pkt_id
        if inject_ma:
            kwargs.setdefault(
                "message_authenticator",
                self._client_enforces_message_authenticator(),
            )
        return cls(**kwargs)

    def create_auth_packet(self, **kwargs) -> "packet.AuthPacket":
        """Build an ``AuthPacket`` pre-populated with this client's context."""
        return self._build_packet(
            packet.AuthPacket, self._AUTH_SERVER_TYPE, inject_ma=True, **kwargs
        )

    def create_acct_packet(self, **kwargs) -> "packet.AcctPacket":
        """Build an ``AcctPacket`` pre-populated with this client's context."""
        return self._build_packet(packet.AcctPacket, self._ACCT_SERVER_TYPE, **kwargs)

    def create_coa_packet(self, **kwargs) -> "packet.CoAPacket":
        """Build a ``CoAPacket`` pre-populated with this client's context."""
        return self._build_packet(packet.CoAPacket, self._COA_SERVER_TYPE, **kwargs)

    def create_status_packet(self, **kwargs) -> "packet.StatusPacket":
        """Build a Status-Server ``StatusPacket`` pre-populated with this
        client's context. Subclasses that route Status-Server packets
        to a specific transport (e.g. async's auth/acct ports) override
        this method to add a ``port`` parameter."""
        return self._build_packet(
            packet.StatusPacket, self._STATUS_SERVER_TYPE, **kwargs
        )
