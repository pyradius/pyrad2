"""EAP method abstraction and registry.

``pyrad2`` clients drive an EAP exchange through a small protocol: the
``EapMethod`` ABC has two hooks — ``start`` to seed the initial
``Access-Request`` and ``respond`` to answer every ``Access-Challenge``
the server returns. Methods are registered under the ``auth_type``
string that callers set on the outgoing ``AuthPacket``; the client
looks one up via ``get_method`` and falls through to a vanilla
non-EAP send when nothing is registered.

Methods are registered as **factories** (zero-argument callables that
return a fresh ``EapMethod`` instance) so multi-round methods that
keep state across challenges — EAP-TLS, EAP-MSCHAPv2, EAP-PEAP — get a
new instance per conversation without leaking state between
unrelated clients. Stateless methods like EAP-MD5 register their class
directly because the class is its own zero-argument factory.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from pyrad2.packet import AuthPacket, Packet


class EapMethod(abc.ABC):
    """Pluggable EAP method driving a RADIUS client's challenge loop.

    Implementations mutate the *same* ``AuthPacket`` object in place
    across the round-trips that span one EAP conversation. The client
    handles transport concerns (id allocation, authenticator
    regeneration, Message-Authenticator); the method handles only the
    EAP payload.
    """

    @abc.abstractmethod
    def start(self, pkt: "AuthPacket") -> None:
        """Seed the initial ``Access-Request`` with this method's payload.

        Called once before the first send. Typically populates the
        ``EAP-Message`` attribute on ``pkt``.
        """

    @abc.abstractmethod
    def respond(self, pkt: "AuthPacket", challenge: "Packet") -> None:
        """Answer an ``Access-Challenge`` by mutating ``pkt`` in place.

        Implementations are responsible for copying the EAP ``State``
        attribute (RFC 2865 §5.24) from ``challenge`` when the server
        sent one — every multi-roundtrip EAP exchange needs it to keep
        the server's session bookkeeping consistent across replies.
        """


MethodFactory = Callable[[], EapMethod]

_METHODS: dict[str, MethodFactory] = {}


def register_method(name: str, factory: MethodFactory) -> None:
    """Register a method factory under an ``auth_type`` string.

    ``name`` is the value callers set on ``AuthPacket.auth_type`` to
    select the method. Re-registering the same name replaces the
    previous factory, which lets tests swap a method's implementation
    without restarting the process.
    """
    _METHODS[name] = factory


def get_method(name: str | None) -> EapMethod | None:
    """Return a fresh instance of the method registered under ``name``.

    Returns ``None`` when ``name`` is ``None`` or unregistered so the
    caller can branch into a non-EAP send path without raising.
    """
    if name is None:
        return None
    factory = _METHODS.get(name)
    if factory is None:
        return None
    return factory()


def registered_methods() -> list[str]:
    """Return a sorted list of registered ``auth_type`` names.

    Exposed mainly for diagnostics and tests — production code should
    look up by name through ``get_method``.
    """
    return sorted(_METHODS)
