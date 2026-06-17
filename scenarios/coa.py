#!/usr/bin/env python
"""End-to-end Change-of-Authorization (RFC 5176) demo.

Sends a CoA-Request from an async Dynamic Authorization Client to an
async Dynamic Authorization Server running in the same process. The
demo server accepts the request with a CoA-ACK.
"""

import asyncio

from loguru import logger

from _shared import (
    COA_PORT,
    DEMO_HOST,
    DEMO_SECRET,
    banner,
    make_dictionary,
    make_remote_host,
    trace_hint,
)
from pyrad2.client_async import ClientAsync
from pyrad2.constants import PacketType
from pyrad2.packet import CoAPacket
from pyrad2.server_async import ServerAsync


class DemoCoAServer(ServerAsync):
    def handle_auth_packet(self, protocol, pkt, addr):
        # Required abstract method on ServerAsync — unused here.
        pass

    def handle_acct_packet(self, protocol, pkt, addr):
        # Required abstract method on ServerAsync — unused here.
        pass

    def handle_coa_packet(self, protocol, pkt, addr):
        logger.info(
            "[server] CoA-Request id={} from {} session={}",
            pkt.id,
            addr,
            pkt.get("Acct-Session-Id"),
        )
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.CoAACK
        logger.info("[server] → CoA-ACK id={}", pkt.id)
        protocol.send_response(reply, addr)


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    banner(f"Starting demo DA server on {DEMO_HOST}:{COA_PORT}")
    server = DemoCoAServer(
        coa_port=COA_PORT,
        hosts={DEMO_HOST: make_remote_host()},
        dictionary=dictionary,
    )
    await server.initialize_transports(enable_coa=True)

    banner("Connecting DA client")
    client = ClientAsync(
        server=DEMO_HOST,
        coa_port=COA_PORT,
        secret=DEMO_SECRET,
        dict=dictionary,
        timeout=2,
    )
    await client.initialize_transports(enable_coa=True)

    try:
        banner("Sending CoA-Request")
        req = client.create_coa_packet(code=PacketType.CoARequest)
        req["User-Name"] = "alice"
        req["Acct-Session-Id"] = "demo-session-001"
        assert isinstance(req, CoAPacket)
        logger.info("[client] → CoA-Request id={}", req.id)

        reply = await asyncio.wait_for(client.send_packet(req), timeout=2)

        banner("Reply received")
        verdict = "CoA-ACK" if reply.code == PacketType.CoAACK else f"code={reply.code}"
        logger.info("[client] ← {} id={}", verdict, reply.id)
    finally:
        await client.deinitialize_transports()
        await server.deinitialize_transports()


if __name__ == "__main__":
    asyncio.run(main())
