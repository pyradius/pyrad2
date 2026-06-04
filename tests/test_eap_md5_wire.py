"""Wire-level regression tests for the EAP-MD5 Access-Request encoder.

The other EAP-MD5 tests (``tests/test_eap.py``,
``tests/test_client.py``, ``tests/test_client_async.py``) cover the
byte-packing helpers and the client-side challenge loop, but they all
either mock ``protocol.send_packet`` or stop short of
``Packet.request_packet`` — none observes the actual bytes a real RADIUS
server would receive.

The invariant pinned here is the one that survives any encoder
restructuring: an Access-Request carrying EAP-Message MUST have exactly
**one** ``Message-Authenticator`` AVP on the wire. Two MAs ship the
zeroed placeholder alongside the real digest and every conformant
server (FreeRADIUS, NPS, MikroTik) rejects them as malformed.
"""

import pytest

from pyrad2 import eap
from pyrad2.dictionary import Dictionary
from pyrad2.packet import AuthPacket


@pytest.fixture
def dictionary() -> Dictionary:
    return Dictionary("examples/dictionary")


def _count_avps(raw: bytes, code: int) -> int:
    """Count AVPs of the given type in an encoded RADIUS packet.

    Walks the RFC 2865 TLV stream past the 20-byte header. Each AVP is
    ``type(1) | length(1) | value(length-2)``; ``length`` is the total
    AVP length including the two header bytes.
    """
    count = 0
    offset = 20  # skip the RADIUS header
    while offset < len(raw):
        attr_code = raw[offset]
        attr_len = raw[offset + 1]
        if attr_code == code:
            count += 1
        offset += attr_len
    return count


def _build_eap_md5_request(dictionary: Dictionary) -> bytes:
    """Build the same shape of Access-Request a real EAP-MD5 client sends.

    Mirrors what ``ClientAsync.create_auth_packet(...)`` followed by
    ``MschapV2Method.start`` (well — ``Md5Method.start``) produces. We
    set ``message_authenticator=True`` at construction the same way the
    ``Client.create_auth_packet`` factory does when ``enforce_ma`` is on,
    so the encoder is exercised exactly as production drives it.
    """
    pkt = AuthPacket(
        id=1,
        secret=b"demo-secret",
        dict=dictionary,
        auth_type="eap-md5",
        User_Name="alice",
        User_Password="hunter2",
        message_authenticator=True,
    )
    method = eap.get_method("eap-md5")
    assert method is not None
    method.start(pkt)
    return pkt.request_packet()


def test_eap_md5_access_request_has_exactly_one_message_authenticator(dictionary):
    # Regression guard. An earlier ``_encode_v10_eap_md5_request`` branch
    # appended a tail Message-Authenticator on top of the one
    # ``ensure_message_authenticator`` already stamped into the attribute
    # list, putting two MAs on the wire. Conformant RADIUS servers
    # (FreeRADIUS, Windows NPS) reject that as malformed; the EAP-MD5
    # scenario hit this against a real server before the encoder branch
    # was removed in favour of the standard random-authenticator path.
    raw = _build_eap_md5_request(dictionary)
    assert _count_avps(raw, 80) == 1


def test_eap_md5_access_request_contains_one_eap_message(dictionary):
    # Independent guard: regardless of the MA bug above, the encoder
    # must not duplicate the EAP-Message AVP. A regression here would
    # mean every EAP method (not just MD5) shipped two payloads.
    raw = _build_eap_md5_request(dictionary)
    assert _count_avps(raw, 79) == 1


def test_eap_md5_request_authenticator_is_seeded(dictionary):
    # The 16 bytes between offset 4 and 20 are the Request Authenticator.
    # For Access-Request it's randomly generated, not derived from body;
    # any all-zero value here would mean ``request_packet`` skipped the
    # ``create_authenticator`` step entirely.
    raw = _build_eap_md5_request(dictionary)
    authenticator = raw[4:20]
    assert len(authenticator) == 16
    assert authenticator != b"\x00" * 16
