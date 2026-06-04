"""Pure-Python MD4 (RFC 1320), internal to pyrad2.

MD4 is cryptographically broken and was removed from default OpenSSL 3
builds; ``hashlib`` and ``cryptography`` no longer expose it on modern
installs. This bundled implementation exists for one purpose only: the
NT Password Hash step of MS-CHAPv2 (RFC 2759 §8.3), which itself is
only present for interop with legacy RADIUS infrastructure. **Do not
use MD4 for new code under any circumstances.**

The module is prefixed with an underscore to advertise that it is
private; callers should use the higher-level helpers in
``pyrad2.mschap``.
"""

import struct


def _F(x: int, y: int, z: int) -> int:
    return ((x & y) | ((~x & 0xFFFFFFFF) & z)) & 0xFFFFFFFF


def _G(x: int, y: int, z: int) -> int:
    return ((x & y) | (x & z) | (y & z)) & 0xFFFFFFFF


def _H(x: int, y: int, z: int) -> int:
    return (x ^ y ^ z) & 0xFFFFFFFF


def _rotl(value: int, shift: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


# RFC 1320 §3.4 — per-round shift schedules and per-round X-index orders.
_ROUND1_S = (3, 7, 11, 19)
_ROUND2_S = (3, 5, 9, 13)
_ROUND3_S = (3, 9, 11, 15)
_ROUND2_K = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
_ROUND3_K = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)


def md4(message: bytes) -> bytes:
    """Return the 16-byte MD4 digest of ``message``."""
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    # Padding (RFC 1320 §3.1): single 0x80 bit, zero pad, 64-bit LE length.
    bit_length = len(message) * 8
    padded = message + b"\x80"
    while (len(padded) * 8) % 512 != 448:
        padded = padded + b"\x00"
    padded = padded + struct.pack("<Q", bit_length)

    for offset in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[offset : offset + 64])
        a, b, c, d = a0, b0, c0, d0

        # Round 1 — F() with no additive constant; X[k] = X[j] in order.
        for j in range(16):
            s = _ROUND1_S[j % 4]
            if j % 4 == 0:
                a = _rotl((a + _F(b, c, d) + x[j]) & 0xFFFFFFFF, s)
            elif j % 4 == 1:
                d = _rotl((d + _F(a, b, c) + x[j]) & 0xFFFFFFFF, s)
            elif j % 4 == 2:
                c = _rotl((c + _F(d, a, b) + x[j]) & 0xFFFFFFFF, s)
            else:
                b = _rotl((b + _F(c, d, a) + x[j]) & 0xFFFFFFFF, s)

        # Round 2 — G() with 0x5A827999, X permuted by _ROUND2_K.
        for j in range(16):
            k = _ROUND2_K[j]
            s = _ROUND2_S[j % 4]
            if j % 4 == 0:
                a = _rotl((a + _G(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)
            elif j % 4 == 1:
                d = _rotl((d + _G(a, b, c) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)
            elif j % 4 == 2:
                c = _rotl((c + _G(d, a, b) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)
            else:
                b = _rotl((b + _G(c, d, a) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)

        # Round 3 — H() with 0x6ED9EBA1, X permuted by _ROUND3_K.
        for j in range(16):
            k = _ROUND3_K[j]
            s = _ROUND3_S[j % 4]
            if j % 4 == 0:
                a = _rotl((a + _H(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            elif j % 4 == 1:
                d = _rotl((d + _H(a, b, c) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            elif j % 4 == 2:
                c = _rotl((c + _H(d, a, b) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            else:
                b = _rotl((b + _H(c, d, a) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0)
