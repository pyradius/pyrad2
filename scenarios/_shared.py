"""Helpers shared by the scenarios under ``scenarios/``.

Each scenario spins up an async server and an async client in the same
process so the full request/reply exchange happens on one set of logs.
This module centralizes the loopback address, secret, ports, dictionary
loading, and the banner the scenarios print between sections.
"""

import os
import sys
from pathlib import Path

from loguru import logger

# Make the repository importable when scenarios are run directly with
# ``python scenarios/<name>.py`` — no install / PYTHONPATH gymnastics.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pyrad2.dictionary import Dictionary  # noqa: E402  (after sys.path fix)
from pyrad2.server import RemoteHost  # noqa: E402

DEMO_HOST = "127.0.0.1"
DEMO_SECRET = b"demo-secret"

# Non-privileged ports so scenarios run without sudo and don't collide with
# a real RADIUS server that might be running on 1812/1813/3799/2083.
AUTH_PORT = 11812
ACCT_PORT = 11813
COA_PORT = 13799
RADSEC_PORT = 12083

# RadSec defaults to the per-RFC 6614 shared secret "radsec" — the client
# and server certs in examples/certs/ are signed for localhost.
RADSEC_SECRET = b"radsec"

_DICTIONARY_PATH = _REPO_ROOT / "examples" / "dictionary"
_CERTS_ROOT = _REPO_ROOT / "examples" / "certs"

# Test certs that ship with the repo. Do not use these in production.
RADSEC_SERVER_CERT = str(_CERTS_ROOT / "server" / "server.cert.pem")
RADSEC_SERVER_KEY = str(_CERTS_ROOT / "server" / "server.key.pem")
RADSEC_CLIENT_CERT = str(_CERTS_ROOT / "client" / "client.cert.pem")
RADSEC_CLIENT_KEY = str(_CERTS_ROOT / "client" / "client.key.pem")
RADSEC_CA_CERT = str(_CERTS_ROOT / "ca" / "ca.cert.pem")


def make_dictionary() -> Dictionary:
    """Load the example FreeRADIUS dictionary that ships with the repo."""
    return Dictionary(str(_DICTIONARY_PATH))


def make_remote_host() -> RemoteHost:
    """RemoteHost entry the demo server uses to authorize the demo client."""
    return RemoteHost(DEMO_HOST, DEMO_SECRET, "demo-client")


def banner(text: str) -> None:
    """Print a visually distinct section header so the log is easy to scan."""
    logger.info("─" * 60)
    logger.info(text)
    logger.info("─" * 60)


def trace_hint() -> None:
    """Surface the PYRAD2_TRACE knob unless the user already turned it on."""
    if not os.environ.get("PYRAD2_TRACE"):
        logger.info("tip: re-run with PYRAD2_TRACE=1 to see wire bytes + decoded AVPs")


def attribute_bytes(value: bytes | str) -> bytes:
    """Coerce a pyrad2 attribute value back to raw bytes.

    Attributes the RFC text calls "string" (``EAP-Message``,
    ``CHAP-Challenge``, ``State``, etc.) are decoded through
    ``tools.decode_string``, which UTF-8-decodes the wire bytes when
    they are valid UTF-8 and otherwise returns ``orig.hex()`` — a plain
    ASCII hex digest with no marker prefix. Server-side handlers that
    want to parse binary EAP/CHAP framing therefore have to reverse the
    conversion. This helper takes either a ``str`` (hex from
    ``decode_string``) or ``bytes`` (raw octets straight off the wire)
    and yields the bytes.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            # Pure-UTF-8 text payload — encode back the way it came in.
            return value.encode("utf-8")
    raise TypeError(f"Cannot coerce {type(value).__name__} to bytes")
