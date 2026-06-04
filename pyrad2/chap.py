"""CHAP password helpers (RFC 1994, RFC 2865 §2.2 / §5.40).

CHAP authenticates an Access-Request by including:

- ``CHAP-Password`` (attribute 3) — one identifier byte followed by an
  MD5 digest of ``id || password || challenge``.
- ``CHAP-Challenge`` (attribute 60) — the challenge bytes. RFC 2865
  permits the server to use the Request Authenticator as the challenge
  when no ``CHAP-Challenge`` attribute is present; pyrad2 always emits
  the explicit attribute to keep the request unambiguous.

CHAP is **not** an EAP method — the server doesn't bounce challenges
back at the client mid-exchange — so it doesn't live under
``pyrad2.eap``. It's its own one-shot transformation applied before
the Access-Request goes out.
"""

import hashlib
import secrets
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from pyrad2.packet import AuthPacket

CHAP_PASSWORD_ATTR = 3
CHAP_CHALLENGE_ATTR = 60


def build_chap_password(chap_id: int, password: bytes, challenge: bytes) -> bytes:
    """Build the ``CHAP-Password`` attribute value.

    Wire layout (17 bytes): one CHAP Identifier byte + the 16-byte
    ``MD5(id || password || challenge)`` digest.

    ``chap_id`` is the value the NAS uses on its CHAP-Identifier byte
    to correlate the response with the challenge. It is independent of
    the RADIUS Identifier and is echoed verbatim into the digest.
    """
    if not 0 <= chap_id <= 0xFF:
        raise ValueError(f"CHAP id must fit in one byte, got {chap_id}")
    id_byte = bytes([chap_id])
    digest = hashlib.md5(id_byte + password + challenge).digest()
    return id_byte + digest


def prepare_chap_request(
    pkt: "AuthPacket",
    password: bytes | str,
    *,
    chap_id: Optional[int] = None,
    challenge: Optional[bytes] = None,
) -> None:
    """Convert a PAP-shaped ``AuthPacket`` to CHAP authentication.

    Pops any existing ``User-Password`` (RFC 2865 §5.2 forbids mixing
    PAP and CHAP credentials in one request) and replaces it with
    freshly-built ``CHAP-Password`` and ``CHAP-Challenge`` attributes.

    Both ``chap_id`` and ``challenge`` are optional and default to
    fresh random values from ``secrets``. Pass explicit values when
    you need deterministic test vectors.
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    if chap_id is None:
        chap_id = secrets.randbelow(256)
    if challenge is None:
        challenge = secrets.token_bytes(16)

    if "User-Password" in pkt:
        del pkt["User-Password"]

    pkt["CHAP-Password"] = build_chap_password(chap_id, password, challenge)
    pkt["CHAP-Challenge"] = challenge
