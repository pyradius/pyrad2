"""Focused tests for the async RADIUS client.

These cover the retry/timeout loop and the EAP-MD5 challenge round-trip
that ``Client`` (sync) and ``ClientAsync`` are expected to handle
identically. Tests drive ``DatagramProtocolClient.__timeout_handler__``
directly rather than relying on wall-clock sleeps.
"""

import asyncio
import os
import threading
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from pyrad2 import client_async, packet
from pyrad2.client_async import ClientAsync, DatagramProtocolClient
from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import IdentifierExhausted
from pyrad2.packet import AcctPacket, AuthPacket, CoAPacket, StatusPacket

from .base import TEST_ROOT_PATH


def _run(coro):
    """Run ``coro`` to completion on a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class _FakeTransport:
    """Minimal stand-in for asyncio.DatagramTransport."""

    def __init__(self):
        self.sent: list[bytes] = []

    def sendto(self, data, addr=None):
        self.sent.append(data)


def _make_protocol(retries=2, timeout=0.05) -> DatagramProtocolClient:
    proto = DatagramProtocolClient(
        server="127.0.0.1",
        port=1812,
        client=MagicMock(),
        retries=retries,
        timeout=timeout,
    )
    proto.transport = _FakeTransport()  # type: ignore[assignment]
    return proto


def _make_request(proto: DatagramProtocolClient, *, packet_id=42, send_date=None):
    """Submit a synthetic pending request without touching the transport."""
    fut: asyncio.Future = asyncio.get_event_loop().create_future()
    pkt = MagicMock()
    pkt.id = packet_id
    pkt.request_packet.return_value = b"raw-bytes"
    proto.pending_requests[packet_id] = {
        "packet": pkt,
        "creation_date": datetime.now(),
        "retries": 0,
        "future": fut,
        "send_date": send_date or datetime.now(),
    }
    return pkt, fut


class TestTimeoutHandler:
    """Retry loop semantics — regression coverage for the two historical bugs."""

    def test_retry_uses_request_packet_lowercase(self):
        """Regression: retry path must call request_packet(), not RequestPacket()."""

        async def scenario():
            proto = _make_protocol(retries=2, timeout=0.05)
            pkt, fut = _make_request(
                proto, send_date=datetime.now() - timedelta(seconds=1)
            )

            task = asyncio.ensure_future(proto.__timeout_handler__())
            # Two ticks: first retries, second exhausts retries.
            await asyncio.sleep(0.2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            return pkt, fut

        pkt, fut = _run(scenario())

        # request_packet() must have been called (sendto invoked) on retry.
        assert pkt.request_packet.called
        # The non-existent PascalCase name must NOT be invoked.
        assert not (hasattr(pkt, "RequestPacket") and pkt.RequestPacket.called)
        # Future ends in TimeoutError once retries are exhausted.
        assert fut.done()
        assert isinstance(fut.exception(), TimeoutError)

    def test_recent_send_does_not_premature_timeout(self):
        """Regression: (send_date - now).seconds wraparound used to fire instantly."""

        async def scenario():
            # Long timeout so a fresh send must NOT trigger any retry.
            proto = _make_protocol(retries=3, timeout=60)
            pkt, fut = _make_request(proto, send_date=datetime.now())

            # Replace asyncio.sleep with one that cancels after a single tick.
            real_sleep = asyncio.sleep

            async def one_shot_sleep(_):
                # Yield control once, then cancel the running task.
                await real_sleep(0)
                raise asyncio.CancelledError

            with patch.object(client_async.asyncio, "sleep", one_shot_sleep):
                try:
                    await proto.__timeout_handler__()
                except asyncio.CancelledError:
                    pass

            return pkt, fut, proto

        pkt, fut, proto = _run(scenario())

        # No retry should have fired and the future must still be pending.
        assert not pkt.request_packet.called
        assert not fut.done()
        assert proto.pending_requests[42]["retries"] == 0

    def test_retries_then_timeout(self):
        """After ``retries`` resends, the future surfaces TimeoutError."""

        async def scenario():
            proto = _make_protocol(retries=2, timeout=0.02)
            pkt, fut = _make_request(
                proto, send_date=datetime.now() - timedelta(seconds=1)
            )

            task = asyncio.ensure_future(proto.__timeout_handler__())
            # Allow enough wall time for retries + final timeout.
            for _ in range(20):
                await asyncio.sleep(0.02)
                if fut.done():
                    break
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            return pkt, fut, proto

        pkt, fut, proto = _run(scenario())

        # request_packet called once per retry (initial send is done by
        # send_packet, which we bypass here).
        assert pkt.request_packet.call_count == 2
        assert isinstance(fut.exception(), TimeoutError)
        # Pending entry cleaned up.
        assert 42 not in proto.pending_requests

    def test_next_wake_up_tracks_remaining_time(self):
        """The chosen sleep duration must be remaining-time, not elapsed-time."""

        sleeps: list[float] = []
        real_sleep = asyncio.sleep

        async def recording_sleep(delay):
            sleeps.append(delay)
            await real_sleep(0)
            raise asyncio.CancelledError

        async def scenario():
            proto = _make_protocol(retries=3, timeout=10.0)
            # Half-elapsed: 5s in, 5s remaining.
            _make_request(proto, send_date=datetime.now() - timedelta(seconds=5))

            with patch.object(client_async.asyncio, "sleep", recording_sleep):
                try:
                    await proto.__timeout_handler__()
                except asyncio.CancelledError:
                    pass

        _run(scenario())

        assert len(sleeps) == 1
        # Should be remaining ≈ 5s, never the elapsed ≈ 5s by coincidence —
        # but importantly never close to 10 (full timeout) or 0.
        assert sleeps[0] > 4.0
        assert sleeps[0] < 6.0


class TestDatagramReceived:
    """Reply-handling path."""

    def test_invalid_reply_does_not_resolve_future(self):
        async def scenario():
            proto = _make_protocol()
            proto.client.dict = None
            proto.client.enforce_ma = False

            pkt = MagicMock()
            pkt.id = 7
            pkt.dict = None
            pkt.secret = b""
            pkt.verify_reply.return_value = False

            fut: asyncio.Future = asyncio.get_event_loop().create_future()
            proto.pending_requests[7] = {
                "packet": pkt,
                "creation_date": datetime.now(),
                "retries": 0,
                "future": fut,
                "send_date": datetime.now(),
            }

            with patch.object(client_async, "Packet") as MockPkt:
                reply = MagicMock()
                reply.code = PacketType.AccessAccept
                reply.id = 7
                MockPkt.return_value = reply
                proto.datagram_received(b"\x02\x07\x00\x14" + b"\x00" * 16, None)

            return fut

        fut = _run(scenario())
        assert not fut.done()

    def test_valid_reply_resolves_future(self):
        async def scenario():
            proto = _make_protocol()
            proto.client.dict = None
            proto.client.enforce_ma = False

            pkt = MagicMock()
            pkt.id = 9
            pkt.dict = None
            pkt.secret = b""
            pkt.verify_reply.return_value = True

            fut: asyncio.Future = asyncio.get_event_loop().create_future()
            proto.pending_requests[9] = {
                "packet": pkt,
                "creation_date": datetime.now(),
                "retries": 0,
                "future": fut,
                "send_date": datetime.now(),
            }

            with patch.object(client_async, "Packet") as MockPkt:
                reply = MagicMock()
                reply.code = PacketType.AccessAccept
                reply.id = 9
                MockPkt.return_value = reply
                proto.datagram_received(b"\x02\x09\x00\x14" + b"\x00" * 16, None)

            return fut, proto

        fut, proto = _run(scenario())
        assert fut.done()
        # Pending entry must be cleaned up after a valid reply.
        assert 9 not in proto.pending_requests


class TestEapMd5Async:
    """EAP-MD5 challenge/response feature parity with the sync client."""

    def setup_method(self):
        self.dictionary = Dictionary(
            os.path.join(TEST_ROOT_PATH, "dicts/dictionary")
        )

    def _make_client(self) -> ClientAsync:
        client = ClientAsync(
            server="127.0.0.1",
            secret=b"secret",
            dict=self.dictionary,
            retries=1,
            timeout=1,
        )
        client.protocol_auth = MagicMock()
        client.protocol_auth.create_id.side_effect = iter(range(100, 200))
        return client

    def test_first_request_carries_eap_identity(self):
        client = self._make_client()
        pkt = AuthPacket(
            id=1,
            secret=b"secret",
            dict=self.dictionary,
            auth_type="eap-md5",
            User_Name="alice",
            User_Password="hunter2",
        )

        captured: list[AuthPacket] = []

        def fake_send(p, fut):
            captured.append(p)

        client.protocol_auth.send_packet.side_effect = fake_send

        # ``_send_auth_packet`` now uses ``get_running_loop()``; wrap the
        # call in a tiny coroutine so the test runs inside a real loop.
        ans_holder: dict[str, asyncio.Future] = {}

        async def _go():
            ans_holder["fut"] = client.send_packet(pkt)

        asyncio.run(_go())
        ans = ans_holder["fut"]

        assert len(captured) == 1
        # EAP-Message attribute (79) must now hold an EAP-Identity Response.
        assert 79 in pkt
        eap_msg = pkt[79][0]
        # Byte 0 is EAP code (2 = Response), byte 4 is EAP type (1 = Identity).
        assert eap_msg[0] == 2
        assert eap_msg[4] == 1
        # Outer future is still pending until the transport answers.
        assert not ans.done()

    def test_access_challenge_triggers_md5_response(self):
        client = self._make_client()
        pkt = AuthPacket(
            id=1,
            secret=b"secret",
            dict=self.dictionary,
            auth_type="eap-md5",
            User_Name="alice",
            User_Password="hunter2",
        )

        sent: list[AuthPacket] = []
        captured_futures: list[asyncio.Future] = []

        def fake_send(p, fut):
            sent.append(p)
            captured_futures.append(fut)

        client.protocol_auth.send_packet.side_effect = fake_send

        async def scenario():
            ans = client.send_packet(pkt)

            # Simulate an Access-Challenge reply on the first future.
            challenge = AuthPacket(
                code=PacketType.AccessChallenge,
                id=1,
                secret=b"secret",
                dict=self.dictionary,
            )
            challenge[24] = [b"opaque-state"]
            # EAP-Request / MD5-Challenge: code=1, id=7, len, type=4,
            # value-size + 16-byte challenge.
            md5_value = b"\x10" + b"\xaa" * 16
            challenge[79] = [
                b"\x01\x07"
                + (5 + len(md5_value)).to_bytes(2, "big")
                + b"\x04"
                + md5_value
            ]
            captured_futures[0].set_result(challenge)

            # Let the done-callback chain fire.
            await asyncio.sleep(0)

            # Second send must have been issued with the MD5 response payload.
            assert len(sent) == 2
            second = sent[1]
            assert 79 in second
            eap_msg = second[79][0]
            # Second EAP code byte is Response (2) and type byte is MD5 (4).
            assert eap_msg[0] == 2
            assert eap_msg[1] == 7  # mirrors challenge EAP id
            assert eap_msg[4] == 4
            # State must be copied across the round-trip.
            assert second[24] == [b"opaque-state"]

            # Now resolve the second future with an Access-Accept.
            accept = AuthPacket(
                code=PacketType.AccessAccept,
                id=second.id,
                secret=b"secret",
                dict=self.dictionary,
            )
            captured_futures[1].set_result(accept)
            await asyncio.sleep(0)

            assert ans.done()
            assert ans.result() is accept

        _run(scenario())

    def test_non_eap_access_accept_resolves_immediately(self):
        """A plain PAP reply must NOT trigger a second send."""
        client = self._make_client()
        pkt = AuthPacket(
            id=1,
            secret=b"secret",
            dict=self.dictionary,
            User_Name="alice",
            User_Password="hunter2",
        )

        sent: list[AuthPacket] = []
        captured_futures: list[asyncio.Future] = []

        def fake_send(p, fut):
            sent.append(p)
            captured_futures.append(fut)

        client.protocol_auth.send_packet.side_effect = fake_send

        async def scenario():
            ans = client.send_packet(pkt)

            accept = AuthPacket(
                code=PacketType.AccessAccept,
                id=1,
                secret=b"secret",
                dict=self.dictionary,
            )
            captured_futures[0].set_result(accept)
            await asyncio.sleep(0)

            assert len(sent) == 1
            assert ans.done()
            assert ans.result() is accept

        _run(scenario())


class TestSendPacketRouting:
    """send_packet must route packets to the matching transport.

    Regression guard: a CoAPacket sent without an initialized CoA
    transport used to silently fall through; an Acct packet sent
    without an Acct transport similarly went to the wrong place.
    """

    def setup_method(self):
        self.dictionary = Dictionary(
            os.path.join(TEST_ROOT_PATH, "dicts/dictionary")
        )

    def _make_client(self) -> ClientAsync:
        client = ClientAsync(
            server="127.0.0.1",
            secret=b"secret",
            dict=self.dictionary,
            retries=1,
            timeout=1,
        )
        client.protocol_auth = MagicMock()
        client.protocol_auth.create_id.side_effect = iter(range(1, 100))
        client.protocol_acct = MagicMock()
        client.protocol_acct.create_id.side_effect = iter(range(100, 200))
        client.protocol_coa = MagicMock()
        client.protocol_coa.create_id.side_effect = iter(range(200, 300))
        return client

    def _run_send_packet(self, client, pkt) -> None:
        """``send_packet`` builds a ``Future`` via ``get_running_loop()``;
        wrap the call so the test executes inside a real event loop."""

        async def _go():
            client.send_packet(pkt)

        asyncio.run(_go())

    def test_acct_packet_uses_acct_protocol(self):
        client = self._make_client()
        pkt = AcctPacket(id=1, secret=b"secret", dict=self.dictionary)

        self._run_send_packet(client, pkt)

        client.protocol_acct.send_packet.assert_called_once()
        client.protocol_coa.send_packet.assert_not_called()
        client.protocol_auth.send_packet.assert_not_called()

    def test_coa_packet_uses_coa_protocol(self):
        client = self._make_client()
        pkt = CoAPacket(id=1, secret=b"secret", dict=self.dictionary)

        self._run_send_packet(client, pkt)

        client.protocol_coa.send_packet.assert_called_once()
        client.protocol_acct.send_packet.assert_not_called()
        client.protocol_auth.send_packet.assert_not_called()

    def test_status_packet_defaults_to_auth_protocol(self):
        client = self._make_client()
        pkt = StatusPacket(id=1, secret=b"secret", dict=self.dictionary)

        self._run_send_packet(client, pkt)

        client.protocol_auth.send_packet.assert_called_once()
        client.protocol_acct.send_packet.assert_not_called()

    def test_coa_without_initialized_transport_raises(self):
        client = self._make_client()
        client.protocol_coa = None
        pkt = CoAPacket(id=1, secret=b"secret", dict=self.dictionary)

        with pytest.raises(Exception):
            client.send_packet(pkt)


class TestIdentifierAllocation:
    """Regression cover for H1/H10: per-transport id scan + typed exhaustion."""

    def test_create_id_skips_in_flight_slots(self):
        # Seed the counter at 41 and mark 42 in-flight; the next id
        # should be 43, not the legacy ``(41+1) % 256 == 42`` collision.
        proto = _make_protocol()
        proto.packet_id = 41
        proto.pending_requests[42] = {"placeholder": True}

        assert proto.create_id() == 43

    def test_create_id_wraps_through_the_full_id_space(self):
        # Block every id except 7. The scan must wrap from 255 → 0
        # and land on the single free slot.
        proto = _make_protocol()
        proto.packet_id = 100
        for i in range(256):
            if i != 7:
                proto.pending_requests[i] = {"placeholder": True}

        assert proto.create_id() == 7

    def test_create_id_raises_identifier_exhausted_when_full(self):
        proto = _make_protocol()
        proto.packet_id = 0
        for i in range(256):
            proto.pending_requests[i] = {"placeholder": True}

        with pytest.raises(IdentifierExhausted):
            proto.create_id()

    def test_send_packet_raises_identifier_exhausted_on_collision(self):
        # Previously raised a bare ``Exception``; callers couldn't tell the
        # exhaustion case apart from a transport failure. Now typed.
        proto = _make_protocol()
        proto.pending_requests[7] = {"placeholder": True}

        pkt = MagicMock()
        pkt.id = 7
        pkt.request_packet.return_value = b"raw"

        with pytest.raises(IdentifierExhausted):
            proto.send_packet(pkt, MagicMock())


class TestModuleLevelCurrentIdThreadSafety:
    """The module-level ``packet.create_id`` is the back-compat path for
    callers constructing ``Packet`` instances without a transport. It now
    serializes its increment so two threads can't read+write the same
    counter and end up with colliding ids.
    """

    def test_create_id_under_thread_contention_produces_unique_increments(self):
        from pyrad2 import packet as packet_mod

        # 256 concurrent callers, each requesting one id. Under a working
        # lock the sequence is a permutation of 0..255 — every value
        # appears exactly once. A racing read-modify-write would produce
        # duplicates as two threads observe the same pre-increment value.
        with packet_mod._CURRENT_ID_LOCK:
            packet_mod.CURRENT_ID = 0

        produced: list[int] = []
        produced_lock = threading.Lock()
        thread_count = 256

        # All threads block on this gate so they actually race rather than
        # serializing on the import path.
        gate = threading.Event()

        def worker():
            gate.wait()
            value = packet_mod.create_id()
            with produced_lock:
                produced.append(value)

        threads = [threading.Thread(target=worker) for _ in range(thread_count)]
        for t in threads:
            t.start()
        gate.set()
        for t in threads:
            t.join()

        assert len(produced) == thread_count
        assert sorted(produced) == list(range(thread_count)), (
            "lock must serialize the increment so every id is unique"
        )


# Quiet unused-import linters: packet is re-exported for downstream
# patching in some test variants.
_ = packet
