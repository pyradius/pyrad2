"""EAP method registry and built-in method implementations.

This package replaces the single-file ``pyrad2/eap.py`` that shipped
through 3.0. All historical names — ``build_eap_identity``,
``inject_eap_identity``, ``apply_eap_md5_challenge``,
``password_from_packet``, ``EAP_MESSAGE_ATTR``, ``STATE_ATTR``,
``USER_NAME_ATTR``, ``USER_PASSWORD_ATTR`` — remain importable from
``pyrad2.eap`` so existing call sites need no change.

The new surface is the ``EapMethod`` ABC plus a small registry
(``register_method`` / ``get_method``). Both the sync ``Client`` and
async ``ClientAsync`` (and the RadSec client) look up the method by
the ``auth_type`` set on the outgoing ``AuthPacket`` and drive it
through a transport-neutral challenge loop, so adding a new method is
a matter of subclassing ``EapMethod`` and calling
``register_method`` — no client changes required.

To add a new method::

    from pyrad2.eap import EapMethod, register_method

    class MschapV2Method(EapMethod):
        def start(self, pkt): ...
        def respond(self, pkt, challenge): ...

    register_method("eap-mschapv2", MschapV2Method)

Callers then set ``pkt.auth_type = "eap-mschapv2"`` and the rest is
automatic.
"""

from pyrad2.eap.base import (
    EapMethod,
    MethodFactory,
    get_method,
    register_method,
    registered_methods,
)
from pyrad2.eap.md5 import (
    EAP_MESSAGE_ATTR,
    STATE_ATTR,
    USER_NAME_ATTR,
    USER_PASSWORD_ATTR,
    Md5Method,
    apply_eap_md5_challenge,
    build_eap_identity,
    build_eap_md5_challenge,
    inject_eap_identity,
    password_from_packet,
)

# The class is its own zero-argument factory (no state to carry across
# conversations), so registering ``Md5Method`` directly is fine.
register_method("eap-md5", Md5Method)

__all__ = [
    "EAP_MESSAGE_ATTR",
    "STATE_ATTR",
    "USER_NAME_ATTR",
    "USER_PASSWORD_ATTR",
    "EapMethod",
    "Md5Method",
    "MethodFactory",
    "apply_eap_md5_challenge",
    "build_eap_identity",
    "build_eap_md5_challenge",
    "get_method",
    "inject_eap_identity",
    "password_from_packet",
    "register_method",
    "registered_methods",
]
