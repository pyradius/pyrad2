#!/usr/bin/env python
"""End-to-end RFC 5080 §2.2.2 duplicate detection demo.

Spins up an async RADIUS server, then opens a raw UDP socket and sends
the *exact same* Access-Request datagram twice — the way a client
retransmits when it suspects a lost reply. The server's handler runs
once; the second datagram is answered from the response cache, byte for
byte. A third datagram (different Request Authenticator) demonstrates
that real new requests still get fresh processing. Run::

    python scenarios/dedup.py

Set ``PYRAD2_TRACE=1`` to also dump every packet's wire bytes and
decoded AVPs as it crosses the loopback::

    PYRAD2_TRACE=1 python scenarios/dedup.py
"""

import asyncio
import secrets

from loguru import logger

from _shared import (
    AUTH_PORT,
    DEMO_HOST,
    DEMO_SECRET,
    banner,
    make_dictionary,
    make_remote_host,
    trace_hint,
)
from pyrad2.constants import PacketType
from pyrad2.packet import AuthPacket
from pyrad2.server_async import ServerAsync


class DemoAuthServer(ServerAsync):
    """Counts handler invocations so we can prove dedup short-circuits the second send."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler_calls = 0

    def handle_auth_packet(self, protocol, pkt, addr):
        self.handler_calls += 1
        logger.info(
            "[server] handler invoked (total={}) id={} authenticator={}",
            self.handler_calls,
            pkt.id,
            pkt.authenticator.hex(),
        )
        reply = self.create_reply_packet(
            pkt,
            **{"Service-Type": "Framed-User", "Framed-IP-Address": "10.0.0.42"},
        )
        reply.code = PacketType.AccessAccept
        protocol.send_response(reply, addr)

    def handle_acct_packet(self, protocol, pkt, addr):
        pass  # required abstract, unused in this scenario


class _ReplyCollector(asyncio.DatagramProtocol):
    """Tiny protocol that pushes every received datagram into an asyncio queue."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr) -> None:
        self.queue.put_nowait(data)


def _build_access_request(dictionary) -> bytes:
    """Encode one Access-Request with a fresh random authenticator+id."""
    req = AuthPacket(
        id=secrets.randbelow(256),
        authenticator=secrets.token_bytes(16),
        secret=DEMO_SECRET,
        dict=dictionary,
    )
    req["User-Name"] = "alice"
    req["NAS-IP-Address"] = "192.168.1.10"
    req["Service-Type"] = "Login-User"
    # Mandatory under the BlastRADIUS-default server. The HMAC is computed
    # over the encoded packet inside request_packet().
    req.add_message_authenticator()
    return req.request_packet()


async def _send_and_recv(transport, protocol, payload, *, label):
    transport.sendto(payload, (DEMO_HOST, AUTH_PORT))
    logger.info("[client] → {} ({} bytes)", label, len(payload))
    data = await asyncio.wait_for(protocol.queue.get(), timeout=2)
    logger.info("[client] ← reply ({} bytes) hex={}", len(data), data.hex())
    return data


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    banner(f"Starting demo server on {DEMO_HOST}:{AUTH_PORT}")
    server = DemoAuthServer(
        auth_port=AUTH_PORT,
        hosts={DEMO_HOST: make_remote_host()},
        dictionary=dictionary,
    )
    await server.initialize_transports(enable_auth=True)

    loop = asyncio.get_running_loop()
    transport, collector = await loop.create_datagram_endpoint(
        _ReplyCollector, local_addr=("127.0.0.1", 0)
    )

    try:
        original = _build_access_request(dictionary)

        banner("First send — handler runs and caches the reply")
        reply_one = await _send_and_recv(
            transport, collector, original, label="Access-Request"
        )

        banner("Retransmit — byte-identical datagram, dedup cache should answer")
        reply_two = await _send_and_recv(
            transport, collector, original, label="Access-Request (retry)"
        )

        banner("Verdict")
        if reply_one == reply_two and server.handler_calls == 1:
            logger.info(
                "✓ Handler ran {} time; both replies are byte-identical "
                "(RFC 5080 §2.2.2 dedup works).",
                server.handler_calls,
            )
        else:
            logger.error(
                "✗ Expected handler_calls=1 and identical replies, got "
                "handler_calls={} and replies_equal={}",
                server.handler_calls,
                reply_one == reply_two,
            )

        banner("Fresh request (different authenticator) — handler must run again")
        fresh = _build_access_request(dictionary)
        await _send_and_recv(transport, collector, fresh, label="Access-Request (new)")
        logger.info(
            "[client] handler invocations after fresh request: {}",
            server.handler_calls,
        )
        assert server.handler_calls == 2, (
            "A request with a new Request Authenticator must not be deduped"
        )
    finally:
        transport.close()
        await server.deinitialize_transports()


if __name__ == "__main__":
    asyncio.run(main())
