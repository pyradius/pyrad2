#!/usr/bin/env python
"""End-to-end RADIUS/1.1 (RFC 9765, experimental) demo over RadSec.

Both server and client advertise ``radius/1.0`` and ``radius/1.1`` via
ALPN. The TLS handshake negotiates the highest mutually supported
version — v1.1 — and the resulting connection drops all MD5 / Message-
Authenticator machinery: User-Password rides the wire in plain text
(visible under ``PYRAD2_TRACE=1``), Request/Response Authenticator is
replaced by a per-connection 32-bit Token, and the Identifier byte is
zero. TLS already authenticates and encrypts the bytes — none of the
legacy obfuscation is needed.

Run with::

    python scenarios/radsec_v11.py

Set ``PYRAD2_TRACE=1`` to see the wire-level details::

    PYRAD2_TRACE=1 python scenarios/radsec_v11.py
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
from pyrad2.radsec.v11 import RadiusVersion
from pyrad2.server import RemoteHost


class DemoV11RadSecServer(BaseRadSecServer):
    async def handle_access_request(self, packet: AuthPacket):
        password = packet.get("User-Password", [b""])[0]
        logger.info(
            "[server] Access-Request user-name={} password={} (RADIUS/{})",
            packet["User-Name"],
            password if isinstance(password, (str, bytes)) else "<missing>",
            "1.1" if packet.radius_version == RadiusVersion.V1_1 else "1.0",
        )
        reply = packet.create_reply(
            **{"Service-Type": "Framed-User", "Framed-IP-Address": "10.0.0.42"},
        )
        reply.code = PacketType.AccessAccept
        logger.info("[server] → Access-Accept")
        return reply

    async def handle_accounting(self, packet: AcctPacket):
        return packet.create_reply()


async def _wait_for_listening(host: str, port: int, timeout: float = 2.0) -> None:
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

    banner(f"Starting RADIUS/1.1-capable RadSec server on {DEMO_HOST}:{RADSEC_PORT}")
    server = DemoV11RadSecServer(
        listen_address=DEMO_HOST,
        listen_port=RADSEC_PORT,
        hosts={DEMO_HOST: RemoteHost(DEMO_HOST, RADSEC_SECRET, "demo-client")},
        dictionary=dictionary,
        certfile=RADSEC_SERVER_CERT,
        keyfile=RADSEC_SERVER_KEY,
        ca_certfile=RADSEC_CA_CERT,
        # Advertise both versions via ALPN; v1.1 wins when both sides agree.
        radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1),
    )
    server_task = asyncio.create_task(server.run())

    try:
        await _wait_for_listening(DEMO_HOST, RADSEC_PORT)

        banner("Connecting RadSec client offering radius/1.0 and radius/1.1")
        client = RadSecClient(
            server=DEMO_HOST,
            port=RADSEC_PORT,
            secret=RADSEC_SECRET,
            dict=dictionary,
            certfile=RADSEC_CLIENT_CERT,
            keyfile=RADSEC_CLIENT_KEY,
            certfile_server=RADSEC_CA_CERT,
            timeout=2,
            radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1),
        )

        try:
            banner("Sending Access-Request (plain User-Password over TLS)")
            req = client.create_auth_packet(
                code=PacketType.AccessRequest, User_Name="alice"
            )
            # set_obfuscated defers encoding until send: plaintext on the
            # wire in v1.1 (RFC 9765 §5.1.1), pw_crypt in v1.0.
            req.set_obfuscated("User-Password", "hunter2")
            req["NAS-IP-Address"] = "192.168.1.10"
            req["Service-Type"] = "Login-User"
            logger.info("[client] → Access-Request user-name=alice")

            reply = await asyncio.wait_for(client.send_packet(req), timeout=3)

            banner("Reply received")
            if reply is None:
                logger.error("[client] no reply received")
                return

            negotiated = (
                "1.1" if client._negotiated_version == RadiusVersion.V1_1 else "1.0"
            )
            logger.info("[client] negotiated RADIUS version: {}", negotiated)
            verdict = (
                "Access-Accept"
                if reply.code == PacketType.AccessAccept
                else f"code={reply.code}"
            )
            logger.info("[client] ← {}", verdict)
            for key in reply.keys():
                logger.info("[client]   {}: {}", key, reply[key])

            if client._negotiated_version == RadiusVersion.V1_1:
                logger.info(
                    "✓ RADIUS/1.1 negotiated — MD5 obfuscation skipped, "
                    "Token used in place of Request Authenticator."
                )
            else:
                logger.warning(
                    "✗ Expected RADIUS/1.1 to be negotiated; got 1.0 instead."
                )
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
