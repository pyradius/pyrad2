"""Unit tests for the RadSec client.

The connection-lifecycle and reply-handling tests in
``test_radsec_server.py`` cover the happy path through an integration
fixture. The cases below target client-only behaviours that are not
exercised end-to-end:

- Transparent EAP-MD5 challenge/response over a single TLS connection,
  mirroring the sync/async client parity.
- Connection reuse when the writer signals it is already closing.
- Fingerprint-allowlist edge cases that bypass Python's own TLS trust.
- Backoff timing between retry attempts on transient stream failures.
"""

import asyncio
import os
from unittest.mock import patch

import pytest

from pyrad2 import eap
from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.packet import AuthPacket
from pyrad2.radsec.client import RadSecClient

from .base import TEST_ROOT_PATH
from .test_radsec_server import (
    CA_CERTFILE,
    CLIENT_CERTFILE,
    CLIENT_KEYFILE,
    FakeRadSecWriter,
)


def _make_client(**overrides) -> RadSecClient:
    defaults = dict(
        server="127.0.0.1",
        secret=b"radsec",
        certfile=CLIENT_CERTFILE,
        keyfile=CLIENT_KEYFILE,
        certfile_server=CA_CERTFILE,
        check_hostname=False,
        timeout=0.05,
        reconnect_backoff=0,
    )
    defaults.update(overrides)
    return RadSecClient(**defaults)


def _build_access_challenge(req: AuthPacket, eap_id: int = 7) -> AuthPacket:
    challenge = AuthPacket(
        code=PacketType.AccessChallenge,
        id=req.id,
        secret=req.secret,
        dict=req.dict,
    )
    challenge.authenticator = b"\x00" * 16
    challenge[24] = [b"opaque-state"]
    md5_value = b"\x10" + b"\xaa" * 16
    challenge[eap.EAP_MESSAGE_ATTR] = [
        b"\x01"
        + bytes([eap_id])
        + (5 + len(md5_value)).to_bytes(2, "big")
        + b"\x04"
        + md5_value
    ]
    return challenge


def _build_access_accept(req: AuthPacket) -> AuthPacket:
    accept = AuthPacket(
        code=PacketType.AccessAccept,
        id=req.id,
        secret=req.secret,
        dict=req.dict,
    )
    accept.authenticator = b"\x00" * 16
    return accept


class TestEapMd5OverRadSec:
    """EAP-MD5 must round-trip transparently over a RadSec connection."""

    def setup_method(self):
        self.dictionary = Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary"))
        self.client = _make_client()
        self.client.dict = self.dictionary

    @pytest.fixture(autouse=True)
    async def _close_client(self):
        # Async cleanup must run inside the test's event loop, so it lives
        # in a fixture rather than ``teardown_method`` (which is sync).
        yield
        await self.client.close()

    async def test_send_packet_handles_access_challenge(self):
        request = self.client.create_auth_packet(
            id=1,
            code=PacketType.AccessRequest,
            auth_type="eap-md5",
            User_Name="alice",
            User_Password="hunter2",
        )

        sent_packets: list[AuthPacket] = []
        replies = iter(
            [
                _build_access_challenge(request, eap_id=7),
                _build_access_accept(request),
            ]
        )

        async def fake_send(pkt):
            # Snapshot the EAP-Message we would have written on the wire
            # before the second leg mutates it again.
            sent_packets.append(pkt[eap.EAP_MESSAGE_ATTR][0])
            return next(replies)

        with patch.object(self.client, "_send_packet", side_effect=fake_send):
            reply = await self.client.send_packet(request)

        # Two physical sends: identity, then MD5 response.
        assert len(sent_packets) == 2

        identity_payload = sent_packets[0]
        assert identity_payload[0] == 2  # EAP-Response
        assert identity_payload[4] == 1  # EAP-Identity

        md5_response = sent_packets[1]
        assert md5_response[0] == 2  # EAP-Response
        assert md5_response[1] == 7  # mirrors challenge id
        assert md5_response[4] == 4  # EAP-MD5

        # State must be carried across the round-trip.
        assert request[24] == [b"opaque-state"]
        assert reply is not None
        assert reply.code == PacketType.AccessAccept

    async def test_non_eap_auth_does_not_trigger_second_send(self):
        request = self.client.create_auth_packet(
            id=1,
            code=PacketType.AccessRequest,
            User_Name="alice",
            User_Password="hunter2",
        )

        call_count = 0

        async def fake_send(pkt):
            nonlocal call_count
            call_count += 1
            return _build_access_accept(request)

        with patch.object(self.client, "_send_packet", side_effect=fake_send):
            reply = await self.client.send_packet(request)

        assert call_count == 1
        assert reply.code == PacketType.AccessAccept


class TestEnsureConnection:
    """A cached writer that signals is_closing() must trigger a reconnect."""

    def setup_method(self):
        self.client = _make_client()

    @pytest.fixture(autouse=True)
    async def _close_client(self):
        yield
        await self.client.close()

    async def test_closing_writer_forces_reopen(self):
        stale_writer = FakeRadSecWriter()
        stale_writer.closed = True  # is_closing() returns True
        self.client._reader = object()
        self.client._writer = stale_writer

        fresh_writer = FakeRadSecWriter()
        fresh_reader = object()

        async def open_connection():
            return fresh_reader, fresh_writer

        with patch.object(self.client, "_open_connection", side_effect=open_connection):
            reader, writer = await self.client._ensure_connection()

        assert reader is fresh_reader
        assert writer is fresh_writer

    async def test_healthy_writer_is_reused(self):
        healthy_writer = FakeRadSecWriter()
        healthy_reader = object()
        self.client._reader = healthy_reader
        self.client._writer = healthy_writer

        async def open_connection():
            raise AssertionError("should not reopen when writer is healthy")

        with patch.object(self.client, "_open_connection", side_effect=open_connection):
            reader, writer = await self.client._ensure_connection()

        assert reader is healthy_reader
        assert writer is healthy_writer


class TestFingerprintVerification:
    """Edge cases around the optional server-fingerprint allowlist."""

    def test_empty_allowlist_accepts_any_writer(self):
        client = _make_client()
        # No allowlist configured: fall back to Python's TLS trust.
        assert client._verify_server_fingerprint(FakeRadSecWriter(cert=None))

    def test_missing_ssl_object_is_rejected(self):
        client = _make_client(allowed_server_fingerprints=["aa" * 32])

        class WriterWithoutSslObject:
            def get_extra_info(self, name, default=None):
                return default

        assert not client._verify_server_fingerprint(WriterWithoutSslObject())

    def test_missing_peer_cert_is_rejected(self):
        client = _make_client(allowed_server_fingerprints=["aa" * 32])
        # FakeRadSecWriter(cert=None) returns an SSL object whose
        # getpeercert() yields None — the fingerprint check must
        # refuse rather than fall through.
        writer = FakeRadSecWriter(cert=None)

        class SslObjectWithoutCert:
            def getpeercert(self, binary_form=False):
                return None

        writer.ssl_object = SslObjectWithoutCert()

        # Re-route get_extra_info to surface our custom ssl object.
        original = writer.get_extra_info

        def get_extra_info(name, default=None):
            if name == "ssl_object":
                return writer.ssl_object
            return original(name, default)

        writer.get_extra_info = get_extra_info  # type: ignore[assignment]

        assert not client._verify_server_fingerprint(writer)


class TestReconnectBackoff:
    """The configured backoff must sleep between attempts, not after the last."""

    def setup_method(self):
        self.client = _make_client(reconnect_backoff=0.1)
        self.client.retries = 3

    @pytest.fixture(autouse=True)
    async def _close_client(self):
        yield
        await self.client.close()

    async def test_sleeps_between_attempts_only(self):
        sleeps: list[float] = []
        real_sleep = asyncio.sleep

        async def record_sleep(delay):
            sleeps.append(delay)
            # Yield control without waiting, to keep the test fast.
            await real_sleep(0)

        async def always_fail(_pkt):
            raise asyncio.IncompleteReadError(partial=b"", expected=4)

        with (
            patch.object(self.client, "_send_packet_once", side_effect=always_fail),
            patch("pyrad2.radsec.client.asyncio.sleep", record_sleep),
        ):
            reply = await self.client._send_packet(object())

        assert reply is None
        # retries=3 means three attempts, so two backoff sleeps in between.
        assert sleeps == [0.1, 0.1]

    async def test_zero_backoff_skips_sleep(self):
        self.client.reconnect_backoff = 0
        self.client.retries = 2

        sleeps: list[float] = []
        real_sleep = asyncio.sleep

        async def record_sleep(delay):
            sleeps.append(delay)
            await real_sleep(0)

        async def always_fail(_pkt):
            raise asyncio.IncompleteReadError(partial=b"", expected=4)

        with (
            patch.object(self.client, "_send_packet_once", side_effect=always_fail),
            patch("pyrad2.radsec.client.asyncio.sleep", record_sleep),
        ):
            await self.client._send_packet(object())

        assert sleeps == []
