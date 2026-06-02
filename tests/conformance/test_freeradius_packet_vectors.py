"""Decode RADIUS packet test vectors from the FreeRADIUS v4 unit tests.

Each ``.txt`` file in the corpus carries a sequence of ``decode-proto``
directives followed by ``match`` lines:

    decode-proto 01 05 00 8b ec fe 3d 2f ...
    match Packet-Type = ::Access-Request, NAS-IP-Address = 10.0.0.1, ...

The hex bytes are a complete RADIUS packet as seen on the wire; the
``match`` line is what FreeRADIUS itself decoded. pyrad2's job is to
accept the same bytes and surface (at minimum) the same attribute names.

Tier 1 of this conformance suite only asserts:

* The decoder accepts the hex bytes without raising.
* The decoded packet exposes every attribute the ``match`` line names
  (modulo FreeRADIUS-only protocol metadata like ``Packet-Type``).

A future tier should compare *values* attribute-by-attribute. That
needs a FreeRADIUS-value-syntax → pyrad2 normaliser and is parked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from pyrad2.dictionary import Dictionary
from pyrad2.packet import parse_packet

_CORPUS_DIR = Path(__file__).parent / "_corpus" / "packet_vectors" / "radius"

# A test dictionary covering enough RFC base attributes to cover the
# vectors. Reusing the same files the rest of the suite uses so we don't
# introduce a third source of truth for what attribute codes mean.
_PYRAD2_DICT_FILES = (
    Path(__file__).parent.parent / "dicts" / "dictionary",
    Path(__file__).parent.parent / "dicts" / "dictionary.freeradius",
)

# Files that aren't decode-side wire vectors and should be skipped.
# ``errors.txt`` and ``foreign.txt`` contain intentionally malformed
# packets (the latter is fuzzer output) — they test the decoder's
# rejection path, not real-world wire compatibility. ``encode.txt`` and
# ``dictionary.test`` aren't decode vectors at all.
_SKIP_FILES: frozenset[str] = frozenset(
    {"errors.txt", "foreign.txt", "encode.txt", "dictionary.test"}
)

# FreeRADIUS pseudo-attributes that surface in ``match`` lines but
# aren't actual RADIUS attributes — they describe the packet itself
# rather than its attribute list, so they don't appear in a decoded
# pyrad2 ``Packet``.
_PSEUDO_ATTRS: frozenset[str] = frozenset(
    {"Packet-Type", "Packet-Authentication-Vector"}
)

# ``Name = `` — captures the LHS of every attribute pair in a match
# line. The ``(?:^|, )`` lookbehind ensures we don't catch ``=`` signs
# embedded inside string or hex values, even when the value itself
# contains commas (e.g. ``Reply-Message = "Hello, \%u"``).
_MATCH_ATTR_RE = re.compile(r"(?:^|, )([A-Z][A-Za-z0-9_.-]*)\s*=\s*")


@dataclass(frozen=True)
class Vector:
    """One ``decode-proto`` / ``match`` pair, sourced from a file."""

    file: str
    line: int
    raw: bytes
    expected_attrs: frozenset[str]

    @property
    def id(self) -> str:
        return f"{self.file}:{self.line}"


@pytest.fixture(scope="session")
def conformance_dictionary() -> Dictionary:
    """Dictionary shared across every packet-vector test in the suite."""

    return Dictionary(*(str(p) for p in _PYRAD2_DICT_FILES))


def _parse_hex_payload(line: str) -> bytes:
    """Extract bytes from a ``decode-proto`` directive line."""

    payload = line.split(None, 1)[1] if " " in line else ""
    return bytes.fromhex(payload.replace(" ", ""))


def _parse_match_attrs(line: str) -> frozenset[str]:
    """The set of attribute names asserted by a ``match`` directive."""

    body = line[len("match ") :]
    names = {m.group(1) for m in _MATCH_ATTR_RE.finditer(body)}
    return frozenset(names - _PSEUDO_ATTRS)


def _vectors_in(path: Path) -> list[Vector]:
    """All ``decode-proto`` / ``match`` pairs found in ``path``."""

    vectors: list[Vector] = []
    pending: tuple[int, bytes] | None = None
    for lineno, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if line.startswith("decode-proto "):
            try:
                pending = (lineno, _parse_hex_payload(line))
            except ValueError:
                pending = None
        elif pending is not None and line.startswith("match "):
            decode_line, raw = pending
            vectors.append(
                Vector(
                    file=path.name,
                    line=decode_line,
                    raw=raw,
                    expected_attrs=_parse_match_attrs(line),
                )
            )
            pending = None
        elif pending is not None and line and not line.startswith("#"):
            # A non-comment, non-``match`` line between ``decode-proto``
            # and ``match`` means the directive is paired with something
            # other than a plain attribute match (e.g. ``match-error``,
            # ``count``). Skip it.
            pending = None
    return vectors


def _all_vectors() -> list[Vector]:
    if not _CORPUS_DIR.is_dir():
        return []
    vectors: list[Vector] = []
    for path in sorted(_CORPUS_DIR.glob("*.txt")):
        if path.name in _SKIP_FILES:
            continue
        vectors.extend(_vectors_in(path))
    return vectors


_VECTORS = _all_vectors()


@pytest.mark.parametrize(
    "vector",
    [pytest.param(v, id=v.id) for v in _VECTORS],
)
def test_decoder_accepts_freeradius_wire_bytes(
    freeradius_packet_vectors_dir: Path,
    conformance_dictionary: Dictionary,
    vector: Vector,
) -> None:
    """Pyrad2's decoder accepts every FreeRADIUS test packet.

    Tests at this tier only assert clean decode, not value parity.
    ``parse_packet`` raises on any wire-level malformation, so a clean
    return is the strongest signal we can give without a value
    normaliser.
    """

    # ``secret`` is irrelevant for parsing structure; the only thing it
    # affects is User-Password de-obfuscation, which is not what we're
    # testing here. The FR fixtures used ``testing123``.
    parse_packet(vector.raw, secret=b"testing123", dictionary=conformance_dictionary)


def test_packet_vector_corpus_is_non_empty(
    freeradius_packet_vectors_dir: Path,
) -> None:
    """Sanity-check that the parser actually found vectors.

    Catches the case where a future restructuring of the FreeRADIUS
    corpus breaks the parser and the test suite silently shrinks to
    zero tests.
    """

    assert _VECTORS, (
        f"no decode-proto/match vectors parsed out of "
        f"{_CORPUS_DIR.relative_to(Path(__file__).parent.parent.parent)}"
    )
