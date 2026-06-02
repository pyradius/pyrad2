"""Conformance-suite fixtures.

The conformance tests run against a FreeRADIUS corpus fetched into
``tests/conformance/_corpus/`` by ``scripts/fetch_freeradius_corpus.py``.
If the corpus isn't present, every conformance test skips with a pointer
to the fetch script — the default ``make test`` therefore stays fast and
network-free.
"""

from __future__ import annotations

from pathlib import Path

import pytest

CORPUS_ROOT = Path(__file__).parent / "_corpus"
DICTIONARIES_DIR = CORPUS_ROOT / "dictionaries" / "share"
PACKET_VECTORS_DIR = CORPUS_ROOT / "packet_vectors" / "radius"

_FETCH_HINT = (
    "FreeRADIUS conformance corpus missing — run "
    "`make conformance-fetch` (or "
    "`uv run python scripts/fetch_freeradius_corpus.py`) to populate "
    "tests/conformance/_corpus/."
)


@pytest.fixture(scope="session")
def freeradius_dictionaries_dir() -> Path:
    if not DICTIONARIES_DIR.is_dir():
        pytest.skip(_FETCH_HINT)
    return DICTIONARIES_DIR


@pytest.fixture(scope="session")
def freeradius_packet_vectors_dir() -> Path:
    if not PACKET_VECTORS_DIR.is_dir():
        pytest.skip(_FETCH_HINT)
    return PACKET_VECTORS_DIR
