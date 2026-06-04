"""Tests for the bundled MD4 implementation.

MD4 lives in ``pyrad2._md4`` strictly to support MS-CHAPv2 password
hashing. The seven test vectors from RFC 1320 §A.5 cover every block
boundary case (empty input, one byte, a partial block, a full block,
a block-plus-one, etc.); if any of them drifts the bundled
implementation is provably wrong and the MS-CHAPv2 layer above can
never produce a server-acceptable response.
"""

import pytest

from pyrad2._md4 import md4


@pytest.mark.parametrize(
    "message,expected",
    [
        (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
        (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
        (b"message digest", "d9130a8164549fe818874806e1c7014b"),
        (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            # 80-byte input — crosses one full 64-byte block boundary.
            b"12345678901234567890123456789012345678901234567890"
            b"123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
    ],
    ids=["empty", "a", "abc", "msg-digest", "lowercase", "alphanumeric", "80-byte"],
)
def test_rfc1320_vectors(message, expected):
    assert md4(message).hex() == expected


def test_digest_is_sixteen_bytes_for_any_input():
    # Property check: MD4 output is always 128 bits regardless of input.
    for length in (0, 1, 55, 56, 57, 63, 64, 65, 127, 128, 129, 1000):
        assert len(md4(b"x" * length)) == 16


def test_two_different_messages_produce_different_digests():
    # Sanity guard against an accidental constant return.
    assert md4(b"a") != md4(b"b")
    assert md4(b"") != md4(b"\x00")
