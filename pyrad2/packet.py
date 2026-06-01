import hashlib
import hmac
import os
import secrets
import struct
from collections import OrderedDict
from typing import Any, Hashable, Optional, Union, Sequence, TypeVar

from loguru import logger

from pyrad2 import tools
from pyrad2.constants import PacketType
from pyrad2.dictionary import Attribute, Dictionary, RadiusAttributeValue
from pyrad2.exceptions import PacketError
from pyrad2.radsec.v11 import RadiusVersion


def hmac_new(*args, **kwargs):
    return hmac.new(*args, digestmod="MD5", **kwargs)


# --- Wire trace ----------------------------------------------------------
# Set PYRAD2_TRACE=1 (or true/yes/on) to dump every packet that crosses
# request_packet / reply_packet / decode_packet. The dump is rendered as
# a single multi-line ``loguru`` INFO message tagged ``[pyrad2 trace]``
# so it interleaves cleanly with the rest of the application's logging.

_TRACE_ENABLED: bool = os.environ.get("PYRAD2_TRACE", "").lower() in (
    "1",
    "true",
    "yes",
    "on",
)


def _trace_hexdump(data: bytes, indent: str = "        ", width: int = 16) -> str:
    """xxd-style hex dump with offset prefix and ASCII gutter."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{offset:04x}  {hex_part:<{width * 3 - 1}}  {ascii_part}")
    return "\n".join(lines)


def _trace_packet(direction: str, raw: bytes, pkt: "Packet") -> None:
    """Log a packet in human-readable form when PYRAD2_TRACE is on."""
    if not _TRACE_ENABLED:
        return
    arrow = "→" if direction == "out" else "←"
    try:
        code_name = PacketType(pkt.code).name
    except ValueError:
        code_name = f"Code-{pkt.code}"

    lines = [
        f"[pyrad2 trace] {arrow} {code_name} id={pkt.id} len={len(raw)}"
    ]
    authenticator = getattr(pkt, "authenticator", None)
    if authenticator:
        lines.append(f"    authenticator: {authenticator.hex()}")
    try:
        keys = list(pkt.keys())
    except Exception:
        keys = []
    if keys:
        lines.append("    attributes:")
        for key in keys:
            try:
                value = pkt[key]
            except Exception as exc:
                lines.append(f"      {key}: <decode error: {exc!s}>")
                continue
            if isinstance(value, dict):
                # TLV / extended / long-extended container.
                for sub_name, sub_values in value.items():
                    lines.append(f"      {key} / {sub_name}: {sub_values!r}")
            else:
                lines.append(f"      {key}: {value!r}")
    lines.append("    raw:")
    lines.append(_trace_hexdump(raw))
    # loguru only prepends its timestamp/level prefix to the first line of
    # a multi-line message, so the hex dump's alignment is preserved.
    logger.info("\n".join(lines))


random_generator = secrets.SystemRandom()

# Current ID
CURRENT_ID = random_generator.randrange(1, 255)


def _md5_keystream_xor(secret: bytes, prev: bytes, block: bytes) -> bytes:
    """One round of the RFC 2865 §5.2 keystream: ``MD5(secret + prev) XOR block``.

    ``block`` must be exactly 16 bytes — every caller pads up-front. The
    int-based XOR is a single CPython op, in contrast to the legacy
    ``bytes((hash[i] ^ block[i],))`` loop that allocates a one-byte
    ``bytes`` object per index and concatenates in O(N²).
    """
    digest = hashlib.md5(secret + prev).digest()
    return (int.from_bytes(digest, "big") ^ int.from_bytes(block, "big")).to_bytes(
        16, "big"
    )

# Used for Typing to indicate you accept only the subclasses
PacketImplementation = Union["AuthPacket", "AcctPacket", "CoAPacket", "StatusPacket"]
ReplyPacketT = TypeVar("ReplyPacketT", bound="Packet")


def _is_radius_11(pkt: Any) -> bool:
    """Return True when this packet carries RFC 9765 RADIUS/1.1 semantics."""
    return getattr(pkt, "radius_version", RadiusVersion.V1_0) == RadiusVersion.V1_1


def _pack_v11_header(
    code: int,
    length: int,
    token: Optional[bytes],
    *,
    zero_token: bool = False,
) -> bytes:
    """Build a RFC 9765 §4.1 packet header.

    Layout (20 bytes): Code(1) | Reserved-1(1, zero) | Length(2) |
    Token(4) | Reserved-2(12, zero).

    A real RADIUS/1.1 packet MUST carry a Token from the per-connection
    counter (§4.1). Missing or wrong-sized Tokens raise ``PacketError``
    rather than silently emitting zeros — a zero Token on the wire is a
    distinct signal (RFC 9765 §6.1 Protocol-Error) and shouldn't be
    indistinguishable from a programming error.

    Pass ``zero_token=True`` only when emitting a Protocol-Error reply
    where the server couldn't determine the original Token.
    """
    if zero_token:
        if token not in (None, b"\x00\x00\x00\x00"):
            raise PacketError(
                "zero_token=True requires token to be None or zero"
            )
        token = b"\x00\x00\x00\x00"
    if token is None:
        raise PacketError(
            "RADIUS/1.1 packet requires a Token (RFC 9765 §4.1). "
            "Set packet.token from a per-connection TokenCounter, or "
            "pass zero_token=True for a Protocol-Error reply."
        )
    if len(token) != 4:
        raise PacketError(
            f"RADIUS/1.1 Token must be exactly 4 bytes, got {len(token)}"
        )
    return struct.pack("!BBH4s12s", code, 0, length, token, b"\x00" * 12)


def prepare_request_message_authenticator(
    pkt: Any, *, require_message_authenticator: bool = False
) -> None:
    """Add Message-Authenticator to outgoing request packets when required."""
    if _is_radius_11(pkt):
        # RFC 9765 §5.2: Message-Authenticator MUST NOT be sent in v1.1.
        return
    code = getattr(pkt, "code", None)
    if code not in (PacketType.AccessRequest, PacketType.StatusServer):
        return

    has_eap_message = getattr(pkt, "has_eap_message", lambda: False)
    if (
        code == PacketType.StatusServer
        or require_message_authenticator
        or has_eap_message()
    ):
        ensure_message_authenticator = getattr(pkt, "ensure_message_authenticator", None)
        if ensure_message_authenticator is not None:
            ensure_message_authenticator()


def prepare_reply_message_authenticator(
    request: Any,
    reply: Any,
    *,
    require_message_authenticator: bool = False,
    require_eap_message_authenticator: bool = True,
) -> None:
    """Add Message-Authenticator to a reply when request or policy requires it.

    ``require_message_authenticator`` is the BlastRADIUS mitigation and is
    scoped to Access replies (Access-Accept/Reject/Challenge). For
    Accounting-Response, CoA-ACK/NAK and Disconnect-ACK/NAK the wire
    body is already integrity-protected by the Response Authenticator MD5,
    so an unconditional MA there would just inflate the packet. The
    mirror rule (request had MA → reply gets MA) and the EAP rule still
    fire for every code.
    """
    if _is_radius_11(request) or _is_radius_11(reply):
        # RFC 9765 §5.2: Message-Authenticator MUST NOT be sent in v1.1.
        return
    request_has_ma = getattr(request, "has_message_authenticator", lambda: False)
    request_has_eap = getattr(request, "has_eap_message", lambda: False)
    reply_has_eap = getattr(reply, "has_eap_message", lambda: False)
    ensure_reply_ma = getattr(reply, "ensure_message_authenticator", None)
    request_code = getattr(request, "code", None)

    require_for_access = (
        require_message_authenticator
        and request_code == PacketType.AccessRequest
    )

    if (
        require_for_access
        or request_has_ma()
        or (require_eap_message_authenticator and (request_has_eap() or reply_has_eap()))
    ):
        if ensure_reply_ma is not None:
            ensure_reply_ma()


class Packet(OrderedDict):
    """Packet acts like a standard python map to provide simple access
    to the RADIUS attributes. Since RADIUS allows for repeated
    attributes the value will always be a sequence. pyrad makes sure
    to preserve the ordering when encoding and decoding packets.

    There are two ways to use the map interface: if attribute
    names are used pyrad take care of en-/decoding data. If
    the attribute type number (or a vendor ID/attribute type
    tuple for vendor attributes) is used you work with the
    raw data.

    Normally you will not use this class directly, but one of the
    `AuthPacket`, `AcctPacket` or `CoAPacket` classes.
    """

    def __init__(
        self,
        code: int = 0,
        id: Optional[int] = None,
        secret: bytes = b"radsec",
        authenticator: Optional[bytes] = None,
        radius_version: RadiusVersion = RadiusVersion.V1_0,
        **attributes,
    ):
        """Initializes a Packet instance.

        Args:
            code (int): Packet type code (8 bits).
            id (int): Packet identification number (8 bits).
            secret (str): Secret needed to communicate with a RADIUS server.
            authenticator (bytes): Optional authenticator
            radius_version (RadiusVersion): RFC 9765 protocol version. Default
                ``V1_0`` preserves historic MD5 behavior; ``V1_1`` flips the
                packet over to the TLS-only profile (no MD5 obfuscation, no
                Message-Authenticator, Token in place of Request/Response
                Authenticator). Set this *before* decoding raw bytes.
            attributes (dict): Attributes to set in the packet
        """
        super().__init__()
        # Must be set before decode_packet runs so attribute de-obfuscation
        # (salt_decrypt etc.) knows which profile to use.
        self.radius_version: RadiusVersion = radius_version
        # Sidecar for attributes whose obfuscation depends on the
        # negotiated radius_version. ``set_obfuscated()`` writes here; the
        # actual encoding happens just before ``request_packet`` /
        # ``reply_packet`` builds the wire bytes. This lets dual-advertise
        # clients assign passwords before the TLS handshake completes.
        self._deferred_obfuscated: "OrderedDict[str, list[Any]]" = OrderedDict()
        self.code = code
        if id is not None:
            self.id = id
        else:
            self.id = create_id()
        if not isinstance(secret, bytes):
            raise TypeError("secret must be a binary string")
        self.secret = secret
        if authenticator is not None and not isinstance(authenticator, bytes):
            raise TypeError("authenticator must be a binary string")
        self.authenticator = authenticator
        # RFC 9765 §4.1: per-connection 32-bit Token, distinct from the
        # legacy 16-byte Authenticator. Kept separate so v1.0 paths can
        # freely reseed self.authenticator (e.g. for pw_crypt) without
        # leaking 12 random bytes into the v1.1 Reserved-2 slot.
        self.token: bytes | None = None
        self.request_authenticator: bytes | None = (
            None  # store request authenticator in reply packets
        )
        self.original_code: int | None = None
        self.message_authenticator = None
        self.raw_packet = None

        # injected by server when grabbing packet
        self.source: list[str]

        if "dict" in attributes:
            self.dict = attributes["dict"]

        if "packet" in attributes:
            self.raw_packet = attributes["packet"]
            self.decode_packet(self.raw_packet)

        if "message_authenticator" in attributes:
            self.message_authenticator = attributes["message_authenticator"]

        for key, value in attributes.items():
            if key in [
                "dict",
                "fd",
                "packet",
                "message_authenticator",
            ]:
                continue
            key = key.replace("_", "-")
            self.add_attribute(key, value)

    def add_message_authenticator(self) -> None:
        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 §5.2: Message-Authenticator MUST NOT be sent in v1.1.
            return
        self.message_authenticator = True
        # Maintain a zero octets content for md5 and hmac calculation.
        self["Message-Authenticator"] = 16 * b"\00"

        if self.id is None:
            self.id = self.create_id()

        if self.authenticator is None and self.code in (
            PacketType.AccessRequest,
            PacketType.StatusServer,
        ):
            self.authenticator = self.create_authenticator()
            self._refresh_message_authenticator()

    def _has_attribute(self, name: str, code: int) -> bool:
        """Return whether an attribute is present by name or numeric code."""
        try:
            if name in self:
                return True
        except AttributeError:
            pass
        return code in self

    def has_message_authenticator(self) -> bool:
        """Return whether this packet includes a Message-Authenticator."""
        return bool(self.message_authenticator) or self._has_attribute(
            "Message-Authenticator", 80
        )

    def has_eap_message(self) -> bool:
        """Return whether this packet includes an EAP-Message."""
        return self._has_attribute("EAP-Message", 79)

    def ensure_message_authenticator(self) -> None:
        """Ensure the packet will be sent with a Message-Authenticator."""
        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 §5.2: Message-Authenticator MUST NOT be sent in v1.1.
            return
        if not self._has_attribute("Message-Authenticator", 80):
            self.add_message_authenticator()
        else:
            self.message_authenticator = True

    def get_message_authenticator(self) -> Optional[bool]:
        self._refresh_message_authenticator()
        return self.message_authenticator

    def _refresh_message_authenticator(self):
        hmac_constructor = hmac_new(self.secret)

        # Maintain a zero octets content for md5 and hmac calculation.
        self["Message-Authenticator"] = 16 * b"\00"
        attr = self._pkt_encode_attributes()

        header = struct.pack("!BBH", self.code, self.id, (20 + len(attr)))

        hmac_constructor.update(header[0:4])
        if self.code in (
            PacketType.AccountingRequest,
            PacketType.DisconnectRequest,
            PacketType.CoARequest,
        ):
            hmac_constructor.update(16 * b"\00")
        elif (
            self.code == PacketType.AccountingResponse
            and self.original_code != PacketType.StatusServer
        ):
            hmac_constructor.update(16 * b"\00")
        else:
            # NOTE: self.authenticator on reply packet is initialized
            #       with request authenticator by design.
            #       For AccessAccept, AccessReject and AccessChallenge
            #       it is needed use original Authenticator.
            #       For AccessAccept, AccessReject and AccessChallenge
            #       it is needed use original Authenticator.
            if self.authenticator is None:
                raise Exception("No authenticator found")
            hmac_constructor.update(self.authenticator)

        hmac_constructor.update(attr)
        self["Message-Authenticator"] = hmac_constructor.digest()

    @staticmethod
    def _zero_message_authenticator(attr: bytes) -> bytes:
        """Return attributes with the Message-Authenticator value zeroed."""
        zeroed = bytearray(attr)
        offset = 0
        found = 0

        while offset < len(attr):
            if offset + 2 > len(attr):
                raise PacketError("Attribute header is corrupt")

            key = attr[offset]
            length = attr[offset + 1]
            if length < 2:
                raise PacketError("Attribute length is too small (%d)" % length)
            if offset + length > len(attr):
                raise PacketError("Attribute length exceeds packet length")

            if key == 80:
                if length != 18:
                    raise PacketError("Message-Authenticator must be 16 bytes")
                found += 1
                zeroed[offset + 2 : offset + length] = 16 * b"\00"

            offset += length

        if found == 0:
            raise PacketError("No Message-Authenticator AVP present")
        if found > 1:
            raise PacketError("Multiple Message-Authenticator AVPs present")

        return bytes(zeroed)

    def verify_message_authenticator(
        self,
        secret: Optional[bytes] = None,
        original_authenticator: Optional[bytes] = None,
        original_code: Optional[int] = None,
    ) -> bool:
        """Verify packet Message-Authenticator.

        Args:
            secret (bytes): The shared secret


        Returns:
            bool: False if verification failed else True
        """
        if self.message_authenticator is None:
            raise Exception("No Message-Authenticator AVP present")

        prev_ma = self["Message-Authenticator"]
        # Set zero bytes for Message-Authenticator for md5 calculation
        if secret is None and self.secret is None:
            raise Exception("Missing secret for HMAC/MD5 verification")

        if secret:
            key = secret
        else:
            key = self.secret

        # If there's a raw packet, use that to calculate the expected
        # Message-Authenticator. While the Packet class keeps multiple
        # instances of an attribute grouped together in the attribute list,
        # other applications may not. Using _pkt_encode_attributes to get
        # the attributes could therefore end up changing the attribute order
        # because of the grouping Packet does, which would cause
        # Message-Authenticator verification to fail. Using the raw packet
        # instead, if present, ensures the verification is done using the
        # attributes exactly as sent.
        if self.raw_packet:
            attr = self.raw_packet[20:]
            attr = self._zero_message_authenticator(attr)
        else:
            self["Message-Authenticator"] = 16 * b"\00"
            attr = self._pkt_encode_attributes()

        header = struct.pack("!BBH", self.code, self.id, (20 + len(attr)))

        hmac_constructor = hmac_new(key)
        hmac_constructor.update(header)
        if self.code in (
            PacketType.AccountingRequest,
            PacketType.DisconnectRequest,
            PacketType.CoARequest,
        ):
            hmac_constructor.update(16 * b"\00")
        elif self.code == PacketType.AccountingResponse:
            if original_code == PacketType.StatusServer:
                if original_authenticator is None:
                    if self.authenticator:
                        original_authenticator = self.authenticator
                    else:
                        raise Exception("Missing original authenticator")
                hmac_constructor.update(original_authenticator)
            else:
                hmac_constructor.update(16 * b"\00")
        elif self.code in (
            PacketType.AccessAccept,
            PacketType.AccessChallenge,
            PacketType.AccessReject,
        ):
            if original_authenticator is None:
                if self.authenticator:
                    # NOTE: self.authenticator on reply packet is initialized
                    #       with request authenticator by design.
                    original_authenticator = self.authenticator
                else:
                    raise Exception("Missing original authenticator")

            hmac_constructor.update(original_authenticator)
        else:
            # On Access-Request and Status-Server use dynamic authenticator
            hmac_constructor.update(self.authenticator)

        hmac_constructor.update(attr)
        self["Message-Authenticator"] = prev_ma[0]
        return hmac.compare_digest(prev_ma[0], hmac_constructor.digest())

    def require_valid_message_authenticator(
        self,
        secret: Optional[bytes] = None,
        original_authenticator: Optional[bytes] = None,
        original_code: Optional[int] = None,
    ) -> None:
        """Raise PacketError unless this packet has a valid Message-Authenticator."""
        try:
            is_valid = self.verify_message_authenticator(
                secret=secret,
                original_authenticator=original_authenticator,
                original_code=original_code,
            )
        except Exception as exc:
            raise PacketError("Message-Authenticator is invalid") from exc

        if not is_valid:
            raise PacketError("Message-Authenticator is invalid")

    def validate_message_authenticator_policy(
        self,
        *,
        require_message_authenticator: bool = False,
        require_eap_message_authenticator: bool = True,
    ) -> None:
        """Validate Message-Authenticator presence and integrity policy.

        ``require_message_authenticator`` is the BlastRADIUS (CVE-2024-3596)
        mitigation. It only applies to Access-Request: the other request
        codes (Accounting-Request, CoA-Request, Disconnect-Request) carry
        a Request Authenticator that is itself an MD5 MAC over the body
        and the shared secret, so the body is already authenticated even
        without an explicit Message-Authenticator AVP. Status-Server has
        its own RFC 5997 MA requirement and is enforced unconditionally.
        """
        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 §5.2: any Message-Authenticator received in v1.1 must
            # be silently discarded; the policy checks below don't apply.
            return
        if not self.has_message_authenticator():
            if self.code == PacketType.StatusServer:
                raise PacketError("Status-Server requires Message-Authenticator")
            if (
                require_message_authenticator
                and self.code == PacketType.AccessRequest
            ):
                raise PacketError("Message-Authenticator attribute is required")
            if require_eap_message_authenticator and self.has_eap_message():
                raise PacketError("EAP-Message requires Message-Authenticator")
            return

        self.require_valid_message_authenticator()

    def create_reply(self, **attributes) -> "Packet":
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        attributes.setdefault("radius_version", self.radius_version)
        return self._set_reply_context(
            Packet(
                id=self.id,
                secret=self.secret,
                authenticator=self.authenticator,
                dict=self.dict,
                **attributes,
            )
        )

    def _set_reply_context(self, reply: ReplyPacketT) -> ReplyPacketT:
        """Store the request code needed for reply authenticators."""
        reply.original_code = self.code
        # RFC 9765 §4.1: the reply MUST echo the request's Token so the
        # client can correlate. Carries over None for v1.0 packets.
        reply.token = self.token
        return reply

    def _decode_value(self, attr: Attribute, value: bytes) -> bytes | str:
        if attr.encrypt == 2 and self.radius_version != RadiusVersion.V1_1:
            # salt decrypt attribute. Skipped in RADIUS/1.1 (RFC 9765 §5.1.3,
            # §5.1.4) — Tunnel-Password / MS-MPPE keys flow as plain octets.
            value = self.salt_decrypt(value)

        if attr.values.has_backward(value):
            return attr.values.get_backward(value)
        else:
            return tools.decode_attr(attr.type, value)

    def _encode_value(self, attr: Attribute, value: bytes | str) -> bytes:
        if attr.values.has_forward(value):
            result = attr.values.get_forward(value)
        else:
            result = tools.encode_attr(attr.type, value)

        if attr.encrypt == 2 and self.radius_version != RadiusVersion.V1_1:
            # salt encrypt attribute. Skipped in RADIUS/1.1 (RFC 9765 §5.1.3,
            # §5.1.4) — Tunnel-Password / MS-MPPE keys ride plain over TLS.
            result = self.salt_crypt(result)

        return result

    def _encode_key_values(
        self, key: Hashable, values: int | bytes | str | Sequence[Any]
    ):
        if not isinstance(key, str):
            return (key, values)

        if not isinstance(values, (list, tuple)):
            values = [values]

        key, _, tag = key.partition(":")
        attr = self.dict.attributes[key]
        key = self._encode_key(key)
        if tag:
            tag_bytes = struct.pack("B", int(tag))
            if attr.type == "integer":
                return (
                    key,
                    [tag_bytes + self._encode_value(attr, v)[1:] for v in values],
                )
            else:
                return (key, [tag_bytes + self._encode_value(attr, v) for v in values])
        else:
            return (key, [self._encode_value(attr, v) for v in values])

    def _encode_key(self, key: Hashable):
        if not isinstance(key, str):
            return key

        attr = self.dict.attributes[key]
        if attr.is_sub_attribute and attr.parent and attr.parent.type == "evs":
            # EVS-VSA: the dictionary already stores the canonical 4-tuple
            # (extended_wrapper, evs_slot, vendor_id, vendor_type) — that's
            # the only place all four are reachable from this attribute.
            return self.dict.attrindex.get_forward(key)
        if (
            attr.vendor and not attr.is_sub_attribute
        ):  # sub attribute keys don't need vendor
            return (self.dict.vendors.get_forward(attr.vendor), attr.code)
        else:
            return attr.code

    def _decode_key(self, key: Hashable) -> Hashable:
        """Turn a key into a string if possible"""

        if self.dict.attrindex.has_backward(key):
            return self.dict.attrindex.get_backward(key)
        return key

    def add_attribute(self, key: str, value: RadiusAttributeValue) -> None:
        """Add an attribute to the packet.

        Args:
            key (str): Attribute name or identification.
            value (Any): The attribute value.
        """
        attr = self.dict.attributes[key.partition(":")[0]]

        (key, value) = self._encode_key_values(key, value)

        if attr.is_sub_attribute and not (
            attr.parent and attr.parent.type == "evs"
        ):
            # TLV-style nesting under the parent code. EVS-VSAs skip this:
            # their 4-tuple key already identifies the slot uniquely so they
            # live flat at the top level of the packet dict.
            tlv = self.setdefault(self._encode_key(attr.parent.name), {})
            encoded = tlv.setdefault(key, [])
        else:
            encoded = self.setdefault(key, [])

        encoded.extend(value)

    def set_obfuscated(self, name: str, value: Any) -> None:
        """Store an obfuscated attribute, deferring encoding until send.

        Use this for attributes whose wire format depends on the negotiated
        RADIUS version (``User-Password``, ``Tunnel-Password``, ``MS-MPPE-*-Key``
        etc.). The plaintext is held aside until the packet is serialized
        — at that point, v1.0 applies ``pw_crypt`` / ``salt_crypt`` and v1.1
        emits the value as plain bytes (RFC 9765 §5.1).

        For RadSec clients that advertise both ``radius/1.0`` and
        ``radius/1.1`` this is the only correct way to assign passwords:
        a direct ``packet["User-Password"] = pw_crypt(...)`` baked-in for
        v1.0 would be unreadable in v1.1 and vice versa.
        """
        self._deferred_obfuscated.setdefault(name, []).append(value)

    def _deferred_storage_key(self, base_name: str) -> Any:
        """Return the ``self``-storage key a deferred attribute would occupy.

        Mirrors ``add_attribute``'s container-shape decision so the main
        encoding loop can skip stored entries that the deferred path
        will re-emit. For TLV sub-attributes that means the parent code
        (not the sub-attribute code); for EVS the 4-tuple flat key; for
        plain vendor attributes the ``(vendor_id, code)`` 2-tuple; for
        standard top-level the raw code.
        """
        attr = self.dict.attributes[base_name]
        if self._is_tlv_sub_attribute(attr):
            return self._encode_key(attr.parent.name)
        return self._encode_key(base_name)

    def _deferred_attribute_codes(self) -> set:
        """Return the storage keys owned by the deferred-obfuscation sidecar.

        ``_pkt_encode_attributes`` uses this to skip stored entries that
        would otherwise duplicate (or contradict) the version-aware
        bytes emitted from the sidecar.
        """
        codes: set = set()
        for name in self._deferred_obfuscated:
            codes.add(self._deferred_storage_key(name.partition(":")[0]))
        return codes

    def _is_tlv_sub_attribute(self, attr: Attribute) -> bool:
        """Return True for TLV / extended / long-extended sub-attributes.

        These nest under a parent code in ``self``'s storage; EVS
        sub-attributes use a 4-tuple flat key instead.
        """
        return attr.is_sub_attribute and not (
            attr.parent and attr.parent.type == "evs"
        )

    def _encode_deferred_value_list(
        self, attr: Attribute, values: list, tag: str
    ) -> list[bytes]:
        """Turn one deferred attribute's plaintext list into wire bytes.

        Applies version-aware obfuscation (``pw_crypt`` for encrypt=1 /
        attribute code 2 in v1.0, ``_encode_value``'s salt path for
        encrypt=2, plain encoding in v1.1) and prefixes a tag byte when
        the deferred key carried one (``"Name:tag"``).
        """
        needs_pw_crypt = (
            attr.code == 2 or attr.encrypt == 1
        ) and self.radius_version != RadiusVersion.V1_1
        encoded_values: list[bytes] = []
        for value in values:
            if needs_pw_crypt:
                pw_crypt = getattr(self, "pw_crypt", None)
                if pw_crypt is None:
                    raise PacketError(
                        "set_obfuscated requires an AuthPacket for "
                        "User-Password obfuscation in RADIUS/1.0"
                    )
                encoded = pw_crypt(value)
            else:
                encoded = self._encode_value(attr, value)
            if tag:
                tag_bytes = struct.pack("B", int(tag))
                if attr.type == "integer":
                    encoded = tag_bytes + encoded[1:]
                else:
                    encoded = tag_bytes + encoded
            encoded_values.append(encoded)
        return encoded_values

    def _seed_parent_from_stored_siblings(
        self, parent_key: Any, owned_sub_codes: set
    ) -> "OrderedDict":
        """Return a copy of the stored ``{sub_code: [...]}`` for ``parent_key``
        with ``owned_sub_codes`` removed.

        Lets the deferred-obfuscation path overlay its own sub-codes onto
        a parent container without dropping non-deferred siblings stored
        directly under the same parent. Returns an empty ``OrderedDict``
        if no parent is stored or the stored value isn't a sub-dict.
        """
        if not OrderedDict.__contains__(self, parent_key):
            return OrderedDict()
        stored = OrderedDict.__getitem__(self, parent_key)
        if not isinstance(stored, dict):
            return OrderedDict()
        return OrderedDict(
            (sub_code, list(values))
            for sub_code, values in stored.items()
            if sub_code not in owned_sub_codes
        )

    def _encode_deferred_obfuscated(self) -> bytes:
        """Encode ``set_obfuscated`` plaintext into ready-to-ship AVPs.

        Pure function: no mutation of ``self`` or the sidecar. Called
        from ``_pkt_encode_attributes`` on every serialization so a retry
        that lands under a different negotiated version regenerates the
        bytes fresh (RFC 9765 §3.5).

        Builds a temporary ``OrderedDict`` mirroring ``self``'s storage
        shape — standard top-level, vendor 2-tuple, EVS 4-tuple, or TLV
        ``{parent: {sub_code: [...]}}`` — then dispatches every entry
        through ``_encode_avp_group``. That shared helper is the same one
        the main loop uses, so deferred and stored attributes can never
        disagree on container framing.

        For TLV / extended / long-extended sub-attributes the deferred
        path also folds in non-deferred stored siblings under the same
        parent. Per-version obfuscation and tag handling live in
        ``_encode_deferred_value_list``; the parent-container merge
        lives in ``_seed_parent_from_stored_siblings``. This function
        is the orchestration that wires the two together.
        """
        if not self._deferred_obfuscated:
            return b""

        owned_sub_codes: "OrderedDict[Any, set]" = OrderedDict()
        for name in self._deferred_obfuscated:
            attr = self.dict.attributes[name.partition(":")[0]]
            if self._is_tlv_sub_attribute(attr):
                parent_key = self._encode_key(attr.parent.name)
                owned_sub_codes.setdefault(parent_key, set()).add(attr.code)

        pending: "OrderedDict[Any, Any]" = OrderedDict()
        for parent_key, sub_codes in owned_sub_codes.items():
            pending[parent_key] = self._seed_parent_from_stored_siblings(
                parent_key, sub_codes
            )

        for name, values in self._deferred_obfuscated.items():
            base_name, _, tag = name.partition(":")
            attr = self.dict.attributes[base_name]
            encoded_values = self._encode_deferred_value_list(attr, values, tag)
            if self._is_tlv_sub_attribute(attr):
                parent_key = self._encode_key(attr.parent.name)
                pending[parent_key].setdefault(attr.code, []).extend(
                    encoded_values
                )
            else:
                # EVS (4-tuple flat key), plain vendor (2-tuple), or
                # standard top-level (int).
                key = self._encode_key(base_name)
                pending.setdefault(key, []).extend(encoded_values)

        return b"".join(
            self._encode_avp_group(code, datalst) for code, datalst in pending.items()
        )

    def get(self, key: Hashable, failobj: Any = None) -> Any:
        try:
            res = self.__getitem__(key)
        except KeyError:
            res = failobj
        return res

    def __getitem__(self, key: Hashable) -> dict | list:
        if not isinstance(key, str):
            return super().__getitem__(key)

        values = super().__getitem__(self._encode_key(key))
        attr = self.dict.attributes[key]
        if attr.type in ("tlv", "extended", "long-extended"):
            # Container attributes — return a map from sub-attribute name to
            # its decoded values. Storage shape is identical across TLV and
            # RFC 6929 extended/long-extended containers.
            map_result: dict = {}
            for sub_attr_key, sub_attr_val in values.items():
                sub_attr_name = attr.sub_attributes[sub_attr_key]
                sub_attr = self.dict.attributes[sub_attr_name]
                for v in sub_attr_val:
                    map_result.setdefault(sub_attr_name, []).append(
                        self._decode_value(sub_attr, v)
                    )
            return map_result
        else:
            list_result: list = []
            for v in values:
                list_result.append(self._decode_value(attr, v))
            return list_result

    def __contains__(self, key: Hashable) -> bool:
        try:
            return super().__contains__(self._encode_key(key))
        except KeyError:
            return False

    has_key = __contains__

    def __delitem__(self, key: Hashable) -> None:
        super().__delitem__(self._encode_key(key))

    def __setitem__(self, key: Hashable, item: Any):
        if isinstance(key, str):
            (key, item) = self._encode_key_values(key, item)
            super().__setitem__(key, item)
        else:
            super().__setitem__(key, item)

    def keys(self):
        return [self._decode_key(key) for key in OrderedDict.keys(self)]

    @staticmethod
    def create_authenticator() -> bytes:
        """Create a packet authenticator. All RADIUS packets contain a sixteen
        byte authenticator which is used to authenticate replies from the
        RADIUS server and in the password hiding algorithm. This function
        returns a suitable random string that can be used as an authenticator.

        Returns:
            bytes: Valid packet authenticator
        """
        return bytes(random_generator.randrange(0, 256) for _ in range(16))

    @staticmethod
    def create_id() -> int:
        """Create a packet ID.  All RADIUS requests have a ID which is used to
        identify a request. This is used to detect retries and replay attacks.
        This function returns a suitable random number that can be used as ID.

        Returns:
            int: ID number
        """
        return random_generator.randrange(0, 256)

    def _serialize_v11(self) -> bytes:
        """Build the on-wire bytes for a RADIUS/1.1 packet.

        Single owner of the v1.1 emission path so every request/reply
        method goes through the same Token / Reserved-2 logic. Returns
        the fully traced raw bytes.
        """
        attr = self._pkt_encode_attributes()
        raw = _pack_v11_header(self.code, 20 + len(attr), self.token) + attr
        _trace_packet("out", raw, self)
        return raw

    def reply_packet(self) -> bytes:
        """Create a ready-to-transmit authentication reply packet.
        Returns a RADIUS packet which can be directly transmitted
        to a RADIUS server. This differs with Packet() in how
        the authenticator is calculated.

        Returns:
            bytes: Raw packet
        """
        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 §4.1 emission. The request's Token was propagated
            # to the reply via create_reply(); the legacy secret /
            # authenticator are unused — TLS authenticates the bytes.
            return self._serialize_v11()

        assert self.authenticator
        assert self.secret is not None

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._pkt_encode_attributes()
        header = struct.pack("!BBH", self.code, self.id, (20 + len(attr)))

        authenticator = hashlib.md5(
            header[0:4] + self.authenticator + attr + self.secret
        ).digest()

        raw = header + authenticator + attr
        _trace_packet("out", raw, self)
        return raw

    def verify_reply(
        self,
        reply: "Packet",
        rawreply: Optional[bytes] = None,
        enforce_ma: bool = False,
    ) -> bool:
        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 §4.1: match request and reply by the 4-byte Token.
            # The MD5 Response Authenticator check is skipped — TLS already
            # authenticated the bytes, and Message-Authenticator must not
            # appear in v1.1 (§5.2).
            if self.token is None or reply.token is None:
                return False
            return reply.token == self.token

        if reply.id != self.id:
            return False

        if rawreply is None:
            rawreply = reply.reply_packet()

        reply._pkt_encode_attributes()
        # The Authenticator field in an Accounting-Response packet is called
        # the Response Authenticator, and contains a one-way MD5 hash
        # calculated over a stream of octets consisting of the Accounting
        # Response Code, Identifier, Length, the Request Authenticator field
        # from the Accounting-Request packet being replied to, and the
        # response attributes if any, followed by the shared secret.  The
        # resulting 16 octet MD5 hash value is stored in the Authenticator
        # field of the Accounting-Response packet.
        hash = hashlib.md5(
            rawreply[0:4] + self.authenticator + rawreply[20:] + self.secret  # type: ignore
        ).digest()

        if not hmac.compare_digest(hash, rawreply[4:20]):
            return False

        if reply.has_message_authenticator():
            try:
                reply.require_valid_message_authenticator(
                    secret=self.secret,
                    original_authenticator=self.authenticator,
                    original_code=self.code,
                )
            except PacketError:
                return False
        elif enforce_ma and self.code == PacketType.AccessRequest:
            # BlastRADIUS (CVE-2024-3596) mitigation applies to
            # Access-Accept/Reject/Challenge. Replies to the other request
            # codes (Accounting-Response, CoA-ACK/NAK, Disconnect-ACK/NAK)
            # are already integrity-protected by the Response Authenticator
            # MD5 verified above, so an absent Message-Authenticator there
            # is not a forgery risk.
            return False
        return True

    # Mapping from byte width to struct format for the VSA inner header.
    _VSA_TYPE_FORMATS = {1: "!B", 2: "!H", 4: "!I"}
    _VSA_LEN_FORMATS = {1: "!B", 2: "!H"}

    def _vendor_format(self, vendor_id: int) -> tuple[int, int]:
        """Return the ``(type_len, len_len)`` VSA wire format for a vendor."""
        dictionary = getattr(self, "dict", None)
        if dictionary is None:
            return (1, 1)
        return dictionary.vendor_format(vendor_id)

    @classmethod
    def _pack_vsa_inner(
        cls, vsa_type: int, value: bytes, type_len: int, len_len: int
    ) -> bytes:
        """Encode the inner VSA header per RFC 2865 §5.26 honoring vendor format.

        ``len_len=0`` produces a header with no length field; the value
        extends to the end of the encapsulating attribute.
        """
        encoded = struct.pack(cls._VSA_TYPE_FORMATS[type_len], vsa_type)
        if len_len:
            total = type_len + len_len + len(value)
            encoded += struct.pack(cls._VSA_LEN_FORMATS[len_len], total)
        return encoded + value

    def _pkt_encode_attribute(self, key: Hashable, value: Any):
        if isinstance(key, tuple):
            vendor_id, vsa_type = key
            type_len, len_len = self._vendor_format(vendor_id)
            inner = self._pack_vsa_inner(vsa_type, value, type_len, len_len)
            value = struct.pack("!L", vendor_id) + inner
            key = 26

        return struct.pack("!BB", key, (len(value) + 2)) + value

    def _pkt_encode_tlv(self, tlv_key: str, tlv_value: Any) -> bytes:
        tlv_attr = self.dict.attributes[self._decode_key(tlv_key)]
        curr_avp = b""
        avps = []
        max_sub_attribute_len = max(map(lambda item: len(item[1]), tlv_value.items()))
        for i in range(max_sub_attribute_len):
            sub_attr_encoding = b""
            for code, datalst in tlv_value.items():
                if i < len(datalst):
                    sub_attr_encoding += self._pkt_encode_attribute(code, datalst[i])
            # split above 255. assuming len of one instance of all sub tlvs is lower than 255
            if (len(sub_attr_encoding) + len(curr_avp)) < 245:
                curr_avp += sub_attr_encoding
            else:
                avps.append(curr_avp)
                curr_avp = sub_attr_encoding
        avps.append(curr_avp)
        tlv_avps = []
        for avp in avps:
            value = struct.pack("!BB", tlv_attr.code, (len(avp) + 2)) + avp
            tlv_avps.append(value)
        if tlv_attr.vendor:
            vendor_avps = b""
            for avp in tlv_avps:
                vendor_avps += (
                    struct.pack(
                        "!BBL",
                        26,
                        (len(avp) + 6),
                        self.dict.vendors.get_forward(tlv_attr.vendor),
                    )
                    + avp
                )
            return vendor_avps
        else:
            return b"".join(tlv_avps)

    def _is_concat_attribute(self, code: Hashable) -> bool:
        """Return True when ``code`` refers to a dictionary attribute marked ``concat``."""
        dictionary = getattr(self, "dict", None)
        if dictionary is None:
            return False
        attr = dictionary.attributes.get(self._decode_key(code))
        return attr is not None and getattr(attr, "concat", False)

    def _container_type(self, code: Hashable) -> Optional[str]:
        """Return the container datatype (``tlv``, ``extended``, ``long-extended``) or None."""
        dictionary = getattr(self, "dict", None)
        if dictionary is None:
            return None
        attr = dictionary.attributes.get(self._decode_key(code))
        if attr is None:
            return None
        if attr.type in ("tlv", "extended", "long-extended"):
            return attr.type
        return None

    @staticmethod
    def _split_into_chunks(data: bytes, max_chunk: int) -> list[bytes]:
        """Split ``data`` into chunks of at most ``max_chunk`` bytes.

        Empty input produces a single empty chunk so callers that need at
        least one fragment (e.g. long-extended) get a deterministic result.
        """
        if not data:
            return [b""]
        return [data[i : i + max_chunk] for i in range(0, len(data), max_chunk)]

    def _pkt_encode_extended(self, parent_code: int, sub_attributes: dict) -> bytes:
        """Encode RFC 6929 extended attributes (types 241-244).

        Each sub-attribute value is emitted as one AVP of the form
        ``[parent][len][ext_type][value]``. The single-byte length field
        caps the value at 252 bytes; longer values require a parent
        declared as ``long-extended``.
        """
        result = b""
        for ext_type, values in sub_attributes.items():
            for value in values:
                if len(value) > 252:
                    raise ValueError(
                        "Extended attribute value too long; declare the "
                        "parent as long-extended to enable fragmentation"
                    )
                result += (
                    struct.pack("!BBB", parent_code, 3 + len(value), ext_type) + value
                )
        return result

    def _pkt_encode_long_extended(
        self, parent_code: int, sub_attributes: dict
    ) -> bytes:
        """Encode RFC 6929 long-extended attributes (types 245-246).

        Values larger than 251 bytes are fragmented across multiple AVPs.
        The More flag (bit 0x80 of the flags byte) is set on every
        fragment except the last so the receiver can reassemble.
        """
        from pyrad2.constants import LONG_EXTENDED_MORE_FLAG

        result = b""
        for ext_type, values in sub_attributes.items():
            for value in values:
                chunks = self._split_into_chunks(value, 251)
                for index, chunk in enumerate(chunks):
                    more = LONG_EXTENDED_MORE_FLAG if index < len(chunks) - 1 else 0
                    result += (
                        struct.pack(
                            "!BBBB", parent_code, 4 + len(chunk), ext_type, more
                        )
                        + chunk
                    )
        return result

    def _pkt_encode_evs(self, key: tuple, value: bytes) -> bytes:
        """Encode one RFC 6929 EVS-VSA AVP (or fragment chain in long form).

        ``key`` is the flat 4-tuple ``(parent, evs_slot, vendor_id,
        vendor_type)``. For extended parents the value is capped at 247
        bytes; for long-extended parents it is fragmented into 246-byte
        chunks, each carrying the same vendor-id and vendor-type with the
        More flag set on every fragment except the last.
        """
        from pyrad2.constants import (
            LONG_EXTENDED_ATTRIBUTE_TYPES,
            LONG_EXTENDED_MORE_FLAG,
        )

        parent_code, ext_type, vendor_id, vsa_type = key
        evs_header = struct.pack("!L", vendor_id) + struct.pack("!B", vsa_type)

        if parent_code in LONG_EXTENDED_ATTRIBUTE_TYPES:
            result = b""
            chunks = self._split_into_chunks(value, 246)
            for index, chunk in enumerate(chunks):
                more = LONG_EXTENDED_MORE_FLAG if index < len(chunks) - 1 else 0
                result += (
                    struct.pack(
                        "!BBBB", parent_code, 9 + len(chunk), ext_type, more
                    )
                    + evs_header
                    + chunk
                )
            return result

        if len(value) > 247:
            raise ValueError(
                "EVS value too large for extended wrapper; declare the "
                "wrapper as long-extended to enable fragmentation"
            )
        return (
            struct.pack("!BBB", parent_code, 8 + len(value), ext_type)
            + evs_header
            + value
        )

    def _encode_avp_group(self, code: Any, datalst: Any) -> bytes:
        """Encode one stored ``(storage-key, [encoded-values])`` group.

        Single owner of the per-key container dispatch — EVS 4-tuples,
        TLV parents, extended / long-extended parents, vendor 2-tuples,
        and standard top-level codes all flow through here. Used by
        both ``_pkt_encode_attributes`` and ``_encode_deferred_obfuscated``
        so the two paths can never diverge on framing.
        """
        if isinstance(code, tuple) and len(code) == 4:
            # EVS-VSA: (parent_code, evs_slot, vendor_id, vendor_type)
            return b"".join(self._pkt_encode_evs(code, v) for v in datalst)
        container = self._container_type(code)
        if container == "tlv":
            return self._pkt_encode_tlv(code, datalst)
        if container == "extended":
            return self._pkt_encode_extended(code, datalst)
        if container == "long-extended":
            return self._pkt_encode_long_extended(code, datalst)
        out = b""
        concat = self._is_concat_attribute(code)
        for data in datalst:
            if concat and len(data) > 253:
                # Split values larger than one AVP into 253-byte chunks;
                # the receiver concatenates per RFC 7268 §3.6.
                for chunk in self._split_into_chunks(data, 253):
                    out += self._pkt_encode_attribute(code, chunk)
            else:
                out += self._pkt_encode_attribute(code, data)
        return out

    def _pkt_encode_attributes(self) -> bytes:
        # Side-effect free serialization: the deferred-obfuscation sidecar
        # is encoded inline at the end and never mutates ``self``. Stored
        # entries that share a code with a deferred attribute are skipped
        # so the deferred declaration wins (its plaintext is authoritative
        # across version flips per RFC 9765 §3.5).
        deferred_codes = self._deferred_attribute_codes()
        result = b""
        for code, datalst in self.items():
            if code in deferred_codes:
                continue
            result += self._encode_avp_group(code, datalst)
        result += self._encode_deferred_obfuscated()
        return result

    def _pkt_decode_vendor_attribute(self, data: bytes) -> list[tuple]:
        if len(data) < 4:
            return [(26, data)]

        (vendor,) = struct.unpack("!L", data[:4])
        type_len, len_len = self._vendor_format(vendor)
        header_len = type_len + len_len
        inner = data[4:]

        if len(inner) < header_len:
            return [(26, data)]

        tlvs: list[tuple] = []
        offset = 0
        while offset + header_len <= len(inner):
            try:
                (atype,) = struct.unpack(
                    self._VSA_TYPE_FORMATS[type_len],
                    inner[offset : offset + type_len],
                )
                if len_len == 0:
                    payload_end = len(inner)
                else:
                    (length_value,) = struct.unpack(
                        self._VSA_LEN_FORMATS[len_len],
                        inner[offset + type_len : offset + header_len],
                    )
                    if length_value < header_len:
                        return [(26, data)]
                    payload_end = offset + length_value
                    if payload_end > len(inner):
                        return [(26, data)]
            except struct.error:
                return [(26, data)]

            payload = inner[offset + header_len : payload_end]
            try:
                if self._pkt_is_tlv_attribute((vendor, atype)):
                    self._pkt_decode_tlv_attribute((vendor, atype), payload)
                else:
                    tlvs.append(((vendor, atype), payload))
            except Exception:
                return [(26, data)]

            offset = payload_end
            if len_len == 0:
                break

        if offset != len(inner):
            return [(26, data)]
        return tlvs

    def _pkt_decode_tlv_attribute(self, code, data):
        sub_attributes = self.setdefault(code, {})
        loc = 0

        while loc < len(data):
            atype, length = struct.unpack("!BB", data[loc : loc + 2])[0:2]
            sub_attributes.setdefault(atype, []).append(data[loc + 2 : loc + length])
            loc += length

    def _pkt_is_tlv_attribute(self, code):
        attr = self.dict.attributes.get(self._decode_key(code))
        return attr is not None and attr.type == "tlv"

    def _is_evs_slot(self, parent_code: int, ext_type: int) -> bool:
        """Return True if ``(parent_code, ext_type)`` is an EVS marker."""
        dictionary = getattr(self, "dict", None)
        if dictionary is None:
            return False
        parent_attr = dictionary.attributes.get(self._decode_key(parent_code))
        if parent_attr is None:
            return False
        sub_name = parent_attr.sub_attributes.get(ext_type)
        if sub_name is None:
            return False
        sub_attr = dictionary.attributes.get(sub_name)
        return sub_attr is not None and sub_attr.type == "evs"

    def _pkt_decode_extended(self, parent_code: int, value: bytes) -> None:
        """Decode one extended AVP (RFC 6929 §2.1).

        If the extended-type slot is registered as an ``evs`` marker, the
        payload is split into vendor-id + vendor-type + value and stored
        under a flat 4-tuple key. Otherwise it stores under
        ``self[parent][ext_type]`` as a regular extended sub-attribute.
        """
        if not value:
            return
        ext_type = value[0]
        payload = value[1:]

        if len(payload) >= 5 and self._is_evs_slot(parent_code, ext_type):
            (vendor_id,) = struct.unpack("!L", payload[:4])
            vsa_type = payload[4]
            self.setdefault(
                (parent_code, ext_type, vendor_id, vsa_type), []
            ).append(payload[5:])
            return

        parent_dict = self.setdefault(parent_code, {})
        parent_dict.setdefault(ext_type, []).append(payload)

    def _pkt_decode_long_extended_fragment(
        self, parent_code: int, value: bytes
    ) -> None:
        """Decode one long-extended fragment (RFC 6929 §2.2), reassembling on M=0.

        Fragments accumulate in ``self._long_ext_buf`` until the More flag
        clears, at which point the joined value is appended to the parent.
        EVS fragments key the buffer on the full 4-tuple so concurrent
        vendor attributes under the same wrapper don't collide.
        """
        from pyrad2.constants import LONG_EXTENDED_MORE_FLAG

        if len(value) < 2:
            return
        ext_type = value[0]
        flags = value[1]
        payload = value[2:]

        if len(payload) >= 5 and self._is_evs_slot(parent_code, ext_type):
            (vendor_id,) = struct.unpack("!L", payload[:4])
            vsa_type = payload[4]
            chunk = payload[5:]
            buf_key = (parent_code, ext_type, vendor_id, vsa_type)
            buf = self._long_ext_buf.setdefault(buf_key, bytearray())
            buf.extend(chunk)
            if not flags & LONG_EXTENDED_MORE_FLAG:
                self.setdefault(buf_key, []).append(bytes(buf))
                del self._long_ext_buf[buf_key]
            return

        buf = self._long_ext_buf.setdefault((parent_code, ext_type), bytearray())
        buf.extend(payload)
        if not flags & LONG_EXTENDED_MORE_FLAG:
            parent_dict = self.setdefault(parent_code, {})
            parent_dict.setdefault(ext_type, []).append(bytes(buf))
            del self._long_ext_buf[(parent_code, ext_type)]

    def decode_packet(self, packet: bytes) -> None:
        """Initialize the object from raw packet data.  Decode a packet as
        received from the network and decode it.

        Args:
            packet packet.Packet: Raw packet
        """
        raw = packet  # preserved for the optional PYRAD2_TRACE dump below
        try:
            (self.code, self.id, length, self.authenticator) = struct.unpack(
                "!BBH16s", packet[0:20]
            )

        except struct.error:
            raise PacketError("Packet header is corrupt")

        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 §4.1: Reserved-1 + Reserved-2 are ignored on receipt.
            # Surface the 4-byte Token separately; keep authenticator==None
            # so v1.0-style consumers can't accidentally read garbage.
            self.token = self.authenticator[:4]
            self.authenticator = None
            self.id = 0
        if len(packet) != length:
            raise PacketError("Packet has invalid length")
        if length > 8192:
            raise PacketError("Packet length is too long (%d)" % length)

        self.clear()
        # Keys are (parent_code, ext_type) for plain long-extended fragments
        # and (parent_code, ext_type, vendor_id, vendor_type) for EVS ones.
        self._long_ext_buf: dict[tuple[int, ...], bytearray] = {}

        packet = packet[20:]
        while packet:
            try:
                (key, attrlen) = struct.unpack("!BB", packet[0:2])
            except struct.error:
                raise PacketError("Attribute header is corrupt")

            if attrlen < 2:
                raise PacketError("Attribute length is too small (%d)" % attrlen)

            value = packet[2:attrlen]
            if key == 26:
                for key, value in self._pkt_decode_vendor_attribute(value):
                    self.setdefault(key, []).append(value)
            elif key == 80:
                # RFC 9765 §5.2: Message-Authenticator MUST NOT appear in
                # RADIUS/1.1 packets. When it does, the receiver MUST
                # silently discard it or treat it as an invalid attribute
                # per RFC 6929 §2.8. Skip both the attribute storage and
                # the message_authenticator flag so handlers can't observe
                # the AVP and so reply-side MA validation is impossible to
                # trigger.
                if self.radius_version != RadiusVersion.V1_1:
                    self.message_authenticator = True
                    self.setdefault(key, []).append(value)
            else:
                container = self._container_type(key)
                if container == "tlv":
                    self._pkt_decode_tlv_attribute(key, value)
                elif container == "extended":
                    self._pkt_decode_extended(key, value)
                elif container == "long-extended":
                    self._pkt_decode_long_extended_fragment(key, value)
                else:
                    self.setdefault(key, []).append(value)

            packet = packet[attrlen:]

        self._merge_concat_attributes()
        _trace_packet("in", raw, self)

    def _merge_concat_attributes(self) -> None:
        """Concatenate split AVPs for attributes flagged with the ``concat`` option.

        Operates on the raw bytes stored under each code, bypassing the
        type-decoding overlays in ``__getitem__`` / ``__setitem__``.
        """
        dictionary = getattr(self, "dict", None)
        if dictionary is None:
            return
        for code in list(OrderedDict.keys(self)):
            attr = dictionary.attributes.get(self._decode_key(code))
            if attr is None or not getattr(attr, "concat", False):
                continue
            chunks = OrderedDict.__getitem__(self, code)
            if isinstance(chunks, list) and len(chunks) > 1:
                OrderedDict.__setitem__(self, code, [b"".join(chunks)])

    def _salt_en_decrypt(self, data, salt):
        if self.request_authenticator is not None:
            last = self.request_authenticator + salt
        else:
            last = self.authenticator + salt

        out = bytearray()
        for offset in range(0, len(data), 16):
            block = _md5_keystream_xor(self.secret, last, data[offset : offset + 16])
            out += block
            # Chain on the previous output (matches the legacy
            # ``last = result[-16:]`` behaviour).
            last = block
        return bytes(out)

    def salt_crypt(self, value) -> bytes:
        """SaltEncrypt

        Args:
            value (str): Plaintext value

        Returns:
            bytes: Obfuscated version of the value
        """

        if isinstance(value, str):
            value = value.encode("utf-8")

        if self.authenticator is None:
            # Deriving the keystream from a zero Authenticator makes the
            # ciphertext recoverable without knowing the shared secret —
            # always seed with fresh entropy.
            self.authenticator = self.create_authenticator()

        # create salt
        random_value = 32768 + random_generator.randrange(0, 32767)
        salt_raw = struct.pack("!H", random_value)

        # length prefixing
        length = struct.pack("B", len(value))
        value = length + value

        # zero padding
        if len(value) % 16 != 0:
            value += b"\x00" * (16 - (len(value) % 16))

        return salt_raw + self._salt_en_decrypt(value, salt_raw)

    def salt_decrypt(self, value: bytes) -> bytes:
        """SaltDecrypt

        Args:
            value (bytes): encrypted value including salt

        Returns:
            bytes: Decrypted plaintext string
        """
        # extract salt
        salt = value[:2]

        # decrypt
        value = self._salt_en_decrypt(value[2:], salt)

        # remove padding
        length = value[0]
        value = value[1 : length + 1]

        return value

    def verify_packet(self) -> bool:
        """Verify request.

        Returns:
            bool: True if verification passed else False
        """
        if self.radius_version == RadiusVersion.V1_1:
            # No request Authenticator MD5 in v1.1 — TLS authenticates.
            return True
        assert self.raw_packet
        hash = hashlib.md5(
            self.raw_packet[0:4] + 16 * b"\x00" + self.raw_packet[20:] + self.secret
        ).digest()
        return hmac.compare_digest(hash, self.authenticator)


class StatusPacket(Packet):
    """RADIUS Status-Server packet for RFC 5997 health checks."""

    def __init__(
        self,
        code: int = PacketType.StatusServer,
        id: Optional[int] = None,
        secret: bytes = b"",
        authenticator: Optional[bytes] = None,
        **attributes,
    ):
        """Initialize a Status-Server packet."""
        super().__init__(code, id, secret, authenticator, **attributes)

    def create_reply(
        self, code: int = PacketType.AccessAccept, **attributes
    ) -> "Packet":
        """Create a response packet for this Status-Server request."""
        attributes.setdefault("radius_version", self.radius_version)
        return self._set_reply_context(
            Packet(
                code=code,
                id=self.id,
                secret=self.secret,
                authenticator=self.authenticator,
                dict=self.dict,
                **attributes,
            )
        )

    def request_packet(self) -> bytes:
        """Create a ready-to-transmit RFC 5997 Status-Server request."""
        if self.id is None:
            self.id = self.create_id()

        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765: Token in the 4-byte slot, Reserved-1 and Reserved-2
            # zero. Status-Server has no Message-Authenticator in v1.1.
            # Take this branch before seeding self.authenticator so v1.1
            # packets don't end up carrying misleading legacy state.
            return self._serialize_v11()

        if self.authenticator is None:
            self.authenticator = self.create_authenticator()

        prepare_request_message_authenticator(self)
        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._pkt_encode_attributes()
        header = struct.pack(
            "!BBH16s", self.code, self.id, (20 + len(attr)), self.authenticator
        )
        raw = header + attr
        _trace_packet("out", raw, self)
        return raw

    def verify_status_request(self) -> bool:
        """Verify an incoming RFC 5997 Status-Server request.

        Mirrors the ``verify_*_request`` methods on the other typed
        packets so callers (e.g. ``RadSecServer._verify_packet``) don't
        need version-specific knowledge.

        - RADIUS/1.0: Status-Server packets MUST carry a valid
          Message-Authenticator (RFC 5997 §3). Returns ``False`` if
          the AVP is missing or its HMAC doesn't match.
        - RADIUS/1.1: Message-Authenticator is forbidden (RFC 9765 §5.2)
          and was already discarded at decode. TLS authenticated the
          bytes — return ``True``.
        """
        if self.radius_version == RadiusVersion.V1_1:
            return True
        try:
            return self.verify_message_authenticator()
        except Exception:
            return False


class AuthPacket(Packet):
    def __init__(
        self,
        code: int = PacketType.AccessRequest,
        id: Optional[int] = None,
        secret: bytes = b"",
        authenticator=None,
        auth_type: str = "pap",
        **attributes,
    ):
        """Initializes an AuthPacket.

        Args:
            code (int): Packet type code (8 bits).
            id (int): Packet identification number (8 bits).
            secret (str): Secret needed to communicate with a RADIUS server.
            authenticator (bytes): Optional authenticator
            auth_type (str): Defaults to `pap`.
            attributes (dict): Attributes to set in the packet
        """
        super().__init__(code, id, secret, authenticator, **attributes)
        self.auth_type = auth_type

    def create_reply(self, **attributes) -> "AuthPacket":
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        attributes.setdefault("radius_version", self.radius_version)
        return self._set_reply_context(
            AuthPacket(
                PacketType.AccessAccept,
                self.id,
                self.secret,
                self.authenticator,
                dict=self.dict,
                auth_type=self.auth_type,
                **attributes,
            )
        )

    def request_packet(self) -> bytes:
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        Returns:
            bytes: Raw packet
        """
        if self.id is None:
            self.id = self.create_id()

        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 emission. The caller (RadSecClient) is responsible
            # for stamping a per-connection Token into self.token before
            # invoking this method. Take this branch *before* seeding
            # self.authenticator so v1.1 packets don't carry misleading
            # legacy state.
            return self._serialize_v11()

        if self.authenticator is None:
            self.authenticator = self.create_authenticator()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._pkt_encode_attributes()
        if self.auth_type == "eap-md5":
            header = struct.pack(
                "!BBH16s", self.code, self.id, (20 + 18 + len(attr)), self.authenticator
            )
            digest = hmac_new(
                self.secret,
                header
                + attr
                + struct.pack("!BB16s", 80, struct.calcsize("!BB16s"), b""),
            ).digest()
            raw = (
                header
                + attr
                + struct.pack("!BB16s", 80, struct.calcsize("!BB16s"), digest)
            )
            _trace_packet("out", raw, self)
            return raw

        header = struct.pack(
            "!BBH16s", self.code, self.id, (20 + len(attr)), self.authenticator
        )

        raw = header + attr
        _trace_packet("out", raw, self)
        return raw

    def pw_decrypt(self, password: bytes) -> str:
        """De-Obfuscate a RADIUS password. RADIUS hides passwords in packets by
        using an algorithm based on the MD5 hash of the packet authenticator
        and RADIUS secret. This function reverses the obfuscation process.

        Although RFC2865 does not explicitly state UTF-8 for the password field,
        the rest of RFC2865 defines UTF-8 as the encoding expected for the decrypted password.

        Args:
            password (str): obfuscated form of password

        Returns:
            str: Plaintext passsword
        """
        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 §5.1.1: User-Password is plain "string" over TLS.
            return password.decode("utf-8", errors="ignore")

        pw = bytearray()
        last = self.authenticator
        for offset in range(0, len(password), 16):
            block = password[offset : offset + 16]
            pw += _md5_keystream_xor(self.secret, last, block)  # type: ignore[arg-type]
            # Decrypt chains on the previous *ciphertext* block, not the
            # previous plaintext output (see the encrypt counterpart).
            last = block

        # This is safe even with UTF-8 encoding since no valid encoding of UTF-8
        # (other than encoding U+0000 NULL) will produce a bytestream containing 0x00 byte.
        pw = pw.rstrip(b"\x00")

        # If the shared secret with the client is not the same, then de-obfuscating the password
        # field may yield illegal UTF-8 bytes. Therefore, in order not to provoke an Exception here
        # (which would be not consistently generated since this will depend on the random data
        # chosen by the client) we simply ignore un-parsable UTF-8 sequences.
        return pw.decode("utf-8", errors="ignore")

    def pw_crypt(self, password: bytes) -> bytes:
        """Obfuscate password.
        RADIUS hides passwords in packets by using an algorithm
        based on the MD5 hash of the packet authenticator and RADIUS
        secret. If no authenticator has been set before calling pw_crypt
        one is created automatically. Changing the authenticator after
        setting a password that has been encrypted using this function
        will not work.

        Args:
            password (str): Plaintext password

        Returns:
            bytes: Obfuscated version of the password
        """
        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 §5.1.1: User-Password is plain "string" over TLS.
            if isinstance(password, str):
                password = password.encode("utf-8")
            return password
        if self.authenticator is None:
            self.authenticator = self.create_authenticator()

        if isinstance(password, str):
            password = password.encode("utf-8")

        buf = password
        if len(password) % 16 != 0:
            buf += b"\x00" * (16 - (len(password) % 16))

        out = bytearray()
        last = self.authenticator
        for offset in range(0, len(buf), 16):
            block = _md5_keystream_xor(
                self.secret, last, buf[offset : offset + 16]  # type: ignore[arg-type]
            )
            out += block
            # Encrypt chains on the previous output ciphertext block.
            last = block

        return bytes(out)

    def verify_chap_passwd(self, userpwd: bytes) -> bool:
        """Verify RADIUS ChapPasswd

        Args:
            userpwd (str): Plaintext password

        Returns:
            bool: True if verification is ok else False

        Raises:
            PacketError: when ``radius_version == V1_1`` and the packet
                doesn't carry a ``CHAP-Challenge`` attribute. In v1.1 the
                Request Authenticator slot is the Token (RFC 9765 §4.1),
                not the legacy random challenge — CHAP-Password without
                CHAP-Challenge is invalid (RFC 9765 §5.1.2). Failing
                loudly here beats falling back to a synthetic random
                authenticator that would silently never match.
        """
        if isinstance(userpwd, str):
            userpwd = userpwd.strip().encode("utf-8")

        chap_password = tools.decode_octets(self.get(3)[0])
        if len(chap_password) != 17:
            return False

        chapid = chap_password[:1]
        password = chap_password[1:]

        if self.radius_version == RadiusVersion.V1_1:
            if "CHAP-Challenge" not in self:
                raise PacketError(
                    "CHAP-Password in RADIUS/1.1 requires an explicit "
                    "CHAP-Challenge attribute (RFC 9765 §5.1.2)"
                )
            challenge = self["CHAP-Challenge"][0]
        else:
            if not self.authenticator:
                self.authenticator = self.create_authenticator()
            challenge = self.authenticator
            if "CHAP-Challenge" in self:
                challenge = self["CHAP-Challenge"][0]

        return hmac.compare_digest(
            password, hashlib.md5(chapid + userpwd + challenge).digest()
        )

    def verify_auth_request(self) -> bool:
        """Verify an incoming Access-Request.

        Access-Request has no MD5 MAC over the body (the Request
        Authenticator is a 16-byte random nonce), so this method enforces
        the structural invariants that are checkable:

        - Packet code is Access-Request.
        - The Request Authenticator is not all-zero (RFC 2865 §3 says it
          MUST be unpredictable; an all-zero value lets an attacker who
          observes the packet recover salt-encrypted attributes such as
          ``Tunnel-Password`` and the MS-MPPE keys without knowing the
          shared secret).

        RADIUS/1.1 packets skip the nonce check — TLS authenticates the
        bytes and ``self.authenticator`` is unset after decode.
        """
        if not self.raw_packet:
            raise ValueError("Raw packet not present")

        if not self.raw_packet[0] == PacketType.AccessRequest:
            return False

        if self.radius_version != RadiusVersion.V1_1:
            if not self.authenticator or self.authenticator == b"\x00" * 16:
                return False

        return True


class AcctPacket(Packet):
    """RADIUS accounting packets. This class is a specialization
    of the generic :obj:`Packet` class for accounting packets.
    """

    def __init__(
        self,
        code: int = PacketType.AccountingRequest,
        id: Optional[int] = None,
        secret: bytes = b"",
        authenticator: Optional[bytes] = None,
        **attributes,
    ):
        """Initializes an Accounting packet.

        Args:
            code (int): Packet type code (8 bits).
            id (int): Packet identification number (8 bits).
            secret (str): Secret needed to communicate with a RADIUS server.
            authenticator (bytes): Optional authenticator
            attributes (dict): Attributes to set in the packet
        """
        super().__init__(code, id, secret, authenticator, **attributes)

    def create_reply(self, **attributes) -> "AcctPacket":
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        attributes.setdefault("radius_version", self.radius_version)
        return self._set_reply_context(
            AcctPacket(
                PacketType.AccountingResponse,
                self.id,
                self.secret,
                self.authenticator,
                dict=self.dict,
                **attributes,
            )
        )

    def verify_acct_request(self) -> bool:
        """Verify request authenticator.

        Returns:
            bool: True if verification passed else False
        """
        return self.verify_packet()

    def request_packet(self) -> bytes:
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        Returns:
            bytes: Raw packet
        """

        if self.id is None:
            self.id = self.create_id()

        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 emission; Token comes from per-connection counter.
            return self._serialize_v11()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._pkt_encode_attributes()
        header = struct.pack("!BBH", self.code, self.id, (20 + len(attr)))
        self.authenticator = hashlib.md5(
            header[0:4] + 16 * b"\x00" + attr + self.secret
        ).digest()

        ans = header + self.authenticator + attr
        _trace_packet("out", ans, self)
        return ans


class CoAPacket(Packet):
    """RADIUS CoA packets. This class is a specialization
    of the generic :obj:`Packet` class for CoA packets.
    """

    def __init__(
        self,
        code: int = PacketType.CoARequest,
        id: Optional[int] = None,
        secret: bytes = b"",
        authenticator: Optional[bytes] = None,
        **attributes,
    ):
        """Initializes a CoA packet.

        Args:
            code (int): Packet type code (8 bits).
            id (int): Packet identification number (8 bits).
            secret (str): Secret needed to communicate with a RADIUS server.
            authenticator (bytes): Optional authenticator
            attributes (dict): Attributes to set in the packet
        """
        super().__init__(code, id, secret, authenticator, **attributes)

    def create_reply(self, **attributes) -> "CoAPacket":
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        attributes.setdefault("radius_version", self.radius_version)
        return self._set_reply_context(
            CoAPacket(
                PacketType.CoAACK,
                self.id,
                self.secret,
                self.authenticator,
                dict=self.dict,
                **attributes,
            )
        )

    def verify_coa_request(self) -> bool:
        """Verify request authenticator.

        :return: True if verification passed else False
        :rtype: boolean
        """
        return self.verify_packet()

    def request_packet(self) -> bytes:
        """Create a ready-to-transmit CoA request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        if self.id is None:
            self.id = self.create_id()

        if self.radius_version == RadiusVersion.V1_1:
            # RFC 9765 emission.
            return self._serialize_v11()

        attr = self._pkt_encode_attributes()

        header = struct.pack("!BBH", self.code, self.id, (20 + len(attr)))
        self.authenticator = hashlib.md5(
            header[0:4] + 16 * b"\x00" + attr + self.secret
        ).digest()

        if self.message_authenticator:
            self._refresh_message_authenticator()
            attr = self._pkt_encode_attributes()
            self.authenticator = hashlib.md5(
                header[0:4] + 16 * b"\x00" + attr + self.secret
            ).digest()

        raw = header + self.authenticator + attr
        _trace_packet("out", raw, self)
        return raw


def create_id() -> int:
    """Generate a packet ID.

    :return: packet ID
    :rtype:  8 bit integer
    """
    global CURRENT_ID

    CURRENT_ID = (CURRENT_ID + 1) % 256
    return CURRENT_ID


def parse_packet(
    data: bytes,
    secret: bytes,
    dictionary: Optional[Dictionary],
    radius_version: RadiusVersion = RadiusVersion.V1_0,
):
    code = data[0]
    packet_class: type[Packet]

    if code == PacketType.AccessRequest:
        packet_class = AuthPacket
    elif code == PacketType.StatusServer:
        packet_class = StatusPacket
    elif code in (PacketType.AccountingRequest, PacketType.AccountingResponse):
        packet_class = AcctPacket
    elif code in (PacketType.CoARequest, PacketType.DisconnectRequest):
        packet_class = CoAPacket
    else:
        packet_class = Packet

    return packet_class(
        packet=data, dict=dictionary, secret=secret, radius_version=radius_version
    )
