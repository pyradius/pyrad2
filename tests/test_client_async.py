"""Focused tests for the async RADIUS client.

These cover the retry/timeout loop and the EAP-MD5 challenge round-trip
that ``Client`` (sync) and ``ClientAsync`` are expected to handle
identically. Tests drive ``DatagramProtocolClient.__timeout_handler__``
directly rather than relying on wall-clock sleeps.
"""

import asyncio
import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from pyrad2 import client_async, packet
from pyrad2.client_async import ClientAsync, DatagramProtocolClient
from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary
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


class TimeoutHandlerTests(unittest.TestCase):
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
        self.assertTrue(pkt.request_packet.called)
        # The non-existent PascalCase name must NOT be invoked.
        self.assertFalse(hasattr(pkt, "RequestPacket") and pkt.RequestPacket.called)
        # Future ends in TimeoutError once retries are exhausted.
        self.assertTrue(fut.done())
        self.assertIsInstance(fut.exception(), TimeoutError)

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
        self.assertFalse(pkt.request_packet.called)
        self.assertFalse(fut.done())
        self.assertEqual(proto.pending_requests[42]["retries"], 0)

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
        self.assertEqual(pkt.request_packet.call_count, 2)
        self.assertIsInstance(fut.exception(), TimeoutError)
        # Pending entry cleaned up.
        self.assertNotIn(42, proto.pending_requests)

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

        self.assertEqual(len(sleeps), 1)
        # Should be remaining ≈ 5s, never the elapsed ≈ 5s by coincidence —
        # but importantly never close to 10 (full timeout) or 0.
        self.assertGreater(sleeps[0], 4.0)
        self.assertLess(sleeps[0], 6.0)


class DatagramReceivedTests(unittest.TestCase):
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
        self.assertFalse(fut.done())

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
        self.assertTrue(fut.done())
        # Pending entry must be cleaned up after a valid reply.
        self.assertNotIn(9, proto.pending_requests)


class EapMd5AsyncTests(unittest.TestCase):
    """EAP-MD5 challenge/response feature parity with the sync client."""

    def setUp(self):
        self.dictionary = Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary"))

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

        self.assertEqual(len(captured), 1)
        # EAP-Message attribute (79) must now hold an EAP-Identity Response.
        self.assertIn(79, pkt)
        eap_msg = pkt[79][0]
        # Byte 0 is EAP code (2 = Response), byte 4 is EAP type (1 = Identity).
        self.assertEqual(eap_msg[0], 2)
        self.assertEqual(eap_msg[4], 1)
        # Outer future is still pending until the transport answers.
        self.assertFalse(ans.done())

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
            self.assertEqual(len(sent), 2)
            second = sent[1]
            self.assertIn(79, second)
            eap_msg = second[79][0]
            # Second EAP code byte is Response (2) and type byte is MD5 (4).
            self.assertEqual(eap_msg[0], 2)
            self.assertEqual(eap_msg[1], 7)  # mirrors challenge EAP id
            self.assertEqual(eap_msg[4], 4)
            # State must be copied across the round-trip.
            self.assertEqual(second[24], [b"opaque-state"])

            # Now resolve the second future with an Access-Accept.
            accept = AuthPacket(
                code=PacketType.AccessAccept,
                id=second.id,
                secret=b"secret",
                dict=self.dictionary,
            )
            captured_futures[1].set_result(accept)
            await asyncio.sleep(0)

            self.assertTrue(ans.done())
            self.assertIs(ans.result(), accept)

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

            self.assertEqual(len(sent), 1)
            self.assertTrue(ans.done())
            self.assertIs(ans.result(), accept)

        _run(scenario())


class SendPacketRoutingTests(unittest.TestCase):
    """send_packet must route packets to the matching transport.

    Regression guard: a CoAPacket sent without an initialized CoA
    transport used to silently fall through; an Acct packet sent
    without an Acct transport similarly went to the wrong place.
    """

    def setUp(self):
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

        with self.assertRaises(Exception):
            client.send_packet(pkt)


# Quiet unused-import linters: packet is re-exported for downstream
# patching in some test variants.
_ = packet
