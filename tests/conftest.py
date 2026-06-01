"""Shared pytest fixtures for the pyrad2 test suite.

Test files reconstruct the same ``Dictionary`` objects on every
``setup_method``. Parsing is cheap individually but the totals add up
across the 500+ tests. The fixtures below build each dictionary once
per session and hand the same instance back to every consumer.

``Dictionary`` is treated as read-only by the test suite. The few
tests that mutate one already do so via ``read_dictionary`` on a
locally-constructed instance, which is unaffected.
"""

import os

import pytest

from pyrad2.dictionary import Dictionary

from .base import TEST_ROOT_PATH


@pytest.fixture(scope="session")
def full_dictionary() -> Dictionary:
    """``tests/data/full`` — the rich fixture used by packet and server tests."""
    return Dictionary(os.path.join(TEST_ROOT_PATH, "data/full"))


@pytest.fixture(scope="session")
def simple_dictionary() -> Dictionary:
    """``tests/data/simple`` — a stripped-down fixture for parser tests."""
    return Dictionary(os.path.join(TEST_ROOT_PATH, "data/simple"))


@pytest.fixture(scope="session")
def chap_dictionary() -> Dictionary:
    """``tests/data/chap`` — fixture covering CHAP attribute types."""
    return Dictionary(os.path.join(TEST_ROOT_PATH, "data/chap"))


@pytest.fixture(scope="session")
def radsec_dictionary() -> Dictionary:
    """``tests/dicts/dictionary`` — FreeRADIUS-style nested includes."""
    return Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary"))
