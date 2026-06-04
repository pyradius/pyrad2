"""MS-CHAPv2 helpers (RFC 2759 + RFC 2548 §2.3).

MS-CHAPv2 is the challenge/response authentication scheme Microsoft
defined for PPP and Windows VPN clients. Plain RADIUS deployments
typically carry it as Microsoft VSAs (RFC 2548) on an Access-Request /
Access-Challenge pair; the EAP variant (EAP-MSCHAPv2) wraps the same
primitives in EAP framing and lives under ``pyrad2.eap.mschapv2``.

**Optional dependency.** The DES step needed for the
``ChallengeResponse`` primitive lives in the ``cryptography``
package — install with::

    pip install pyrad2[mschap]

MD4 (also required by MS-CHAPv2) is bundled in ``pyrad2._md4`` because
modern OpenSSL builds no longer ship it. Both halves are loaded lazily
so the rest of pyrad2 stays importable even when the extra isn't
installed.

**Security note.** MS-CHAPv2 is cryptographically broken — the
challenge/response primitive can be reduced to a single DES key search.
Use it strictly for legacy interop, never as a primary authentication
factor on a new deployment.
"""

import hashlib
from typing import TYPE_CHECKING

from pyrad2._md4 import md4

if TYPE_CHECKING:
    from pyrad2.packet import AuthPacket

# Surface a consistent error message at every entry point that needs the
# optional dependency.
_MSCHAP_EXTRA_HINT = (
    "MS-CHAPv2 requires the 'cryptography' package for DES. "
    "Install it with: pip install pyrad2[mschap]"
)


def _expand_des_key(key7: bytes) -> bytes:
    """Spread a 7-byte DES sub-key over 8 bytes with zero-parity LSBs.

    The MS-CHAPv2 spec (RFC 2759 §8.6) hashes passwords into 16 bytes
    and pads them to 21, then carves out three 7-byte DES keys. DES
    itself ignores the LSB of each byte (the parity bit), so we shift
    the 56 key bits left by one and leave the LSBs as zero.
    """
    if len(key7) != 7:
        raise ValueError(f"DES sub-key must be 7 bytes, got {len(key7)}")
    k = key7
    return bytes(
        [
            k[0] & 0xFE,
            ((k[0] << 7) | (k[1] >> 1)) & 0xFE,
            ((k[1] << 6) | (k[2] >> 2)) & 0xFE,
            ((k[2] << 5) | (k[3] >> 3)) & 0xFE,
            ((k[3] << 4) | (k[4] >> 4)) & 0xFE,
            ((k[4] << 3) | (k[5] >> 5)) & 0xFE,
            ((k[5] << 2) | (k[6] >> 6)) & 0xFE,
            (k[6] << 1) & 0xFE,
        ]
    )


def _des_encrypt(key7: bytes, plaintext8: bytes) -> bytes:
    """Single-DES encrypt one 8-byte block under a 7-byte sub-key.

    Modern ``cryptography`` releases no longer expose single-DES as a
    public primitive — only TripleDES — so we feed TripleDES three
    copies of the same 8-byte expanded key. ``TripleDES(K||K||K)``
    reduces to single-DES because ``E_K(D_K(E_K(P))) == E_K(P)``.
    """
    if len(plaintext8) != 8:
        raise ValueError(f"DES block must be 8 bytes, got {len(plaintext8)}")
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
    except ImportError as e:
        raise ImportError(_MSCHAP_EXTRA_HINT) from e

    expanded = _expand_des_key(key7)
    # ECB is correct here despite its general-case dangers: RFC 2759
    # §8.5 / §8.6 specify a *single 8-byte block* DES encryption — the
    # whole MS-CHAPv2 response is three independent one-block transforms.
    # Modes that chain blocks (CBC, CTR, GCM) are not applicable when
    # there is only one block, and changing the wire transform would
    # break interop with every conforming RADIUS server. The well-known
    # MS-CHAPv2 cryptanalytic weakness (Marlinspike/Ray, 2012) is in the
    # protocol design — three DES keys derived from a 16-byte hash —
    # not in our use of ECB. See the module docstring for the
    # accompanying "use for legacy interop only" warning.
    cipher = Cipher(TripleDES(expanded * 3), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext8) + encryptor.finalize()


def nt_password_hash(password: bytes | str) -> bytes:
    """Compute the NT Password Hash (RFC 2759 §8.3).

    The Microsoft password hash is ``MD4(password_utf16le)`` — the
    password is encoded as little-endian UCS-2/UTF-16 with no
    terminator and no length prefix.
    """
    if isinstance(password, str):
        password = password.encode("utf-16-le")
    return md4(password)


def hash_nt_password_hash(password_hash: bytes) -> bytes:
    """Compute the ``PasswordHashHash`` (RFC 2759 §8.4).

    Just MD4 applied to the 16-byte NT Password Hash. Used inside the
    Authenticator Response computation to prove the server also knew
    the password.
    """
    if len(password_hash) != 16:
        raise ValueError(f"NT password hash must be 16 bytes, got {len(password_hash)}")
    return md4(password_hash)


def challenge_hash(
    peer_challenge: bytes,
    authenticator_challenge: bytes,
    user_name: bytes | str,
) -> bytes:
    """RFC 2759 §8.2 — SHA-1 truncated to 8 bytes.

    ``user_name`` is the *bare* username — any domain prefix
    (``DOMAIN\\user``) is stripped by the caller per the spec.
    """
    if isinstance(user_name, str):
        user_name = user_name.encode("utf-8")
    if len(peer_challenge) != 16:
        raise ValueError(f"Peer challenge must be 16 bytes, got {len(peer_challenge)}")
    if len(authenticator_challenge) != 16:
        raise ValueError(
            f"Authenticator challenge must be 16 bytes, got {len(authenticator_challenge)}"
        )
    h = hashlib.sha1()
    h.update(peer_challenge)
    h.update(authenticator_challenge)
    h.update(user_name)
    return h.digest()[:8]


def challenge_response(challenge8: bytes, password_hash: bytes) -> bytes:
    """RFC 2759 §8.5 — 24-byte response from challenge + password hash.

    Pads the 16-byte hash to 21 bytes, carves it into three 7-byte DES
    keys, and encrypts the 8-byte challenge under each. Returns the
    concatenated 24-byte result.
    """
    if len(challenge8) != 8:
        raise ValueError(f"Challenge must be 8 bytes, got {len(challenge8)}")
    if len(password_hash) != 16:
        raise ValueError(f"Password hash must be 16 bytes, got {len(password_hash)}")
    z = password_hash + b"\x00" * 5
    return (
        _des_encrypt(z[0:7], challenge8)
        + _des_encrypt(z[7:14], challenge8)
        + _des_encrypt(z[14:21], challenge8)
    )


def generate_nt_response(
    authenticator_challenge: bytes,
    peer_challenge: bytes,
    user_name: bytes | str,
    password: bytes | str,
) -> bytes:
    """RFC 2759 §8.1 — produce the 24-byte NT-Response.

    The end-to-end primitive most callers want: takes the two 16-byte
    challenges, the username, and the cleartext password, and returns
    the 24 bytes that go into the ``Response`` field of
    ``MS-CHAP2-Response`` (RFC 2548 §2.3.2) or the EAP-MSCHAPv2
    response packet.
    """
    challenge = challenge_hash(peer_challenge, authenticator_challenge, user_name)
    pw_hash = nt_password_hash(password)
    return challenge_response(challenge, pw_hash)


def build_mschap2_response(
    ident: int,
    peer_challenge: bytes,
    nt_response: bytes,
    flags: int = 0,
) -> bytes:
    """Build the 50-byte ``MS-CHAP2-Response`` VSA payload (RFC 2548 §2.3.2).

    Wire layout::

        Ident(1) | Flags(1) | Peer-Challenge(16) | Reserved(8) | Response(24)

    The ``Reserved`` field is always 8 zero octets. ``Flags`` is 0 in
    every conformant deployment — set non-zero only if a specific NAS
    requires it.
    """
    if not 0 <= ident <= 0xFF:
        raise ValueError(f"Ident must fit in one byte, got {ident}")
    if not 0 <= flags <= 0xFF:
        raise ValueError(f"Flags must fit in one byte, got {flags}")
    if len(peer_challenge) != 16:
        raise ValueError(f"Peer challenge must be 16 bytes, got {len(peer_challenge)}")
    if len(nt_response) != 24:
        raise ValueError(f"NT response must be 24 bytes, got {len(nt_response)}")
    return bytes([ident, flags]) + peer_challenge + b"\x00" * 8 + nt_response


# Both literal strings come from RFC 2759 §8.7. They are the only
# constants in the Authenticator Response derivation; treat them as
# wire data and do not normalise.
_AUTH_RESPONSE_MAGIC_1 = b"Magic server to client signing constant"
_AUTH_RESPONSE_MAGIC_2 = b"Pad to make it do more than one iteration"


def generate_authenticator_response(
    password: bytes | str,
    nt_response: bytes,
    peer_challenge: bytes,
    authenticator_challenge: bytes,
    user_name: bytes | str,
) -> bytes:
    """RFC 2759 §8.7 — produce the 42-byte ``S=...`` authenticator response.

    The server returns this in the ``MS-CHAP2-Success`` VSA (RFC 2548
    §2.3.3); the client recomputes it locally and compares. The output
    is an ASCII bytestring of the form ``b"S=" + 40 uppercase hex
    characters`` — exactly what appears on the wire.
    """
    if len(nt_response) != 24:
        raise ValueError(f"NT response must be 24 bytes, got {len(nt_response)}")
    password_hash = nt_password_hash(password)
    password_hash_hash = hash_nt_password_hash(password_hash)

    h1 = hashlib.sha1()
    h1.update(password_hash_hash)
    h1.update(nt_response)
    h1.update(_AUTH_RESPONSE_MAGIC_1)
    inner = h1.digest()

    server_challenge = challenge_hash(
        peer_challenge, authenticator_challenge, user_name
    )

    h2 = hashlib.sha1()
    h2.update(inner)
    h2.update(server_challenge)
    h2.update(_AUTH_RESPONSE_MAGIC_2)
    final = h2.digest()

    return b"S=" + final.hex().upper().encode("ascii")


def verify_authenticator_response(
    password: bytes | str,
    nt_response: bytes,
    peer_challenge: bytes,
    authenticator_challenge: bytes,
    user_name: bytes | str,
    received: bytes,
) -> bool:
    """Validate the server's ``MS-CHAP2-Success`` Authenticator Response.

    RFC 2548 §2.3.3 specifies the ``MS-CHAP2-Success`` VSA value as a
    one-byte ``MS-CHAP-Identifier`` followed by the ``Success-Message``
    ``"S=<authenticator> M=<message>"``. This helper locates the
    ``S=`` marker and compares the 42-byte authenticator slice against
    the locally-recomputed expected value; ``M=<message>`` (an optional
    operator-facing note) and any preceding identifier byte are
    ignored.
    """
    expected = generate_authenticator_response(
        password, nt_response, peer_challenge, authenticator_challenge, user_name
    )
    if not isinstance(received, (bytes, bytearray)):
        raise TypeError("received must be bytes")
    received = bytes(received)
    idx = received.find(b"S=")
    if idx < 0:
        return False
    return received[idx : idx + 42] == expected


def prepare_mschap2_request(
    pkt: "AuthPacket",
    *,
    user_name: bytes | str,
    password: bytes | str,
    authenticator_challenge: bytes,
    peer_challenge: bytes,
    ident: int = 0,
    flags: int = 0,
) -> bytes:
    """Stamp an ``AuthPacket`` with the two MS-CHAPv2 VSAs and return the NT-Response.

    Mutates ``pkt`` in place — ``User-Password`` is removed,
    ``MS-CHAP-Challenge`` and ``MS-CHAP2-Response`` VSAs are set — and
    returns the 24-byte NT-Response so the caller can later verify the
    server's Authenticator Response without recomputing the chain.
    """
    if "User-Password" in pkt:
        del pkt["User-Password"]

    nt_response = generate_nt_response(
        authenticator_challenge, peer_challenge, user_name, password
    )
    pkt["MS-CHAP-Challenge"] = authenticator_challenge
    pkt["MS-CHAP2-Response"] = build_mschap2_response(
        ident, peer_challenge, nt_response, flags=flags
    )
    return nt_response
