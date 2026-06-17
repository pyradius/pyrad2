#!/usr/bin/env python
"""End-to-end RadSec (RFC 6614) Access-Request demo.

Spins up a ``RadSecServer`` on a non-privileged port using the test
certificates that ship in ``examples/certs/``, sends one Access-Request
from a ``RadSecClient`` in the same event loop, prints both sides, and
exits.

The test certs are signed for ``localhost`` / ``127.0.0.1``. Do not
reuse them outside a development context.

Run with::

    python scenarios/radsec_auth.py

Set ``PYRAD2_TRACE=1`` to also dump every packet's wire bytes and
decoded AVPs as they cross the TLS connection.
"""

import asyncio

from loguru import logger

from _shared import (
    DEMO_HOST,
    RADSEC_CA_CERT,
    RADSEC_CLIENT_CERT,
    RADSEC_CLIENT_KEY,
    RADSEC_PORT,
    RADSEC_SECRET,
    RADSEC_SERVER_CERT,
    RADSEC_SERVER_KEY,
    banner,
    make_dictionary,
    trace_hint,
)
from pyrad2.constants import PacketType
from pyrad2.packet import AcctPacket, AuthPacket
from pyrad2.radsec.client import RadSecClient
from pyrad2.radsec.server import RadSecServer as BaseRadSecServer
from pyrad2.server import RemoteHost


class DemoRadSecServer(BaseRadSecServer):
    async def handle_access_request(self, packet: AuthPacket):
        logger.info(
            "[server] Access-Request id={} user-name={}",
            packet.id,
            packet["User-Name"],
        )
        reply = packet.create_reply(
            **{
                "Service-Type": "Framed-User",
                "Framed-IP-Address": "10.0.0.42",
            },
        )
        reply.code = PacketType.AccessAccept
        logger.info("[server] → Access-Accept id={}", packet.id)
        return reply

    async def handle_accounting(self, packet: AcctPacket):
        # Required abstract method — unused in this scenario.
        return packet.create_reply()


async def _wait_for_listening(host: str, port: int, timeout: float = 2.0) -> None:
    """Poll the TCP socket until the server's TLS listener is accepting."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        try:
            _, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except (ConnectionRefusedError, OSError):
            await asyncio.sleep(0.05)
    raise TimeoutError(f"RadSec server did not bind {host}:{port} in {timeout}s")


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    banner(f"Starting demo RadSec server on {DEMO_HOST}:{RADSEC_PORT}")
    server = DemoRadSecServer(
        listen_address=DEMO_HOST,
        listen_port=RADSEC_PORT,
        hosts={DEMO_HOST: RemoteHost(DEMO_HOST, RADSEC_SECRET, "demo-client")},
        dictionary=dictionary,
        certfile=RADSEC_SERVER_CERT,
        keyfile=RADSEC_SERVER_KEY,
        ca_certfile=RADSEC_CA_CERT,
    )
    server_task = asyncio.create_task(server.run())

    try:
        await _wait_for_listening(DEMO_HOST, RADSEC_PORT)

        banner("Connecting RadSec client (mutual TLS)")
        client = RadSecClient(
            server=DEMO_HOST,
            port=RADSEC_PORT,
            secret=RADSEC_SECRET,
            dict=dictionary,
            certfile=RADSEC_CLIENT_CERT,
            keyfile=RADSEC_CLIENT_KEY,
            certfile_server=RADSEC_CA_CERT,
            timeout=2,
        )

        try:
            banner("Sending Access-Request over TLS")
            req = client.create_auth_packet(
                code=PacketType.AccessRequest, User_Name="alice"
            )
            req["NAS-IP-Address"] = "192.168.1.10"
            req["Service-Type"] = "Login-User"
            logger.info("[client] → Access-Request id={} user-name=alice", req.id)

            reply = await asyncio.wait_for(client.send_packet(req), timeout=3)

            banner("Reply received")
            if reply is None:
                logger.error("[client] no reply received")
                return
            verdict = (
                "Access-Accept"
                if reply.code == PacketType.AccessAccept
                else f"code={reply.code}"
            )
            logger.info("[client] ← {} id={}", verdict, reply.id)
            for key in reply.keys():
                logger.info("[client]   {}: {}", key, reply[key])
        finally:
            await client.close()
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, Exception):
            pass


if __name__ == "__main__":
    asyncio.run(main())
