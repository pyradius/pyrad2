#!/usr/bin/env python
"""End-to-end CHAP Access-Request demo.

The client builds an Access-Request, then ``prepare_chap_request``
swaps the cleartext User-Password for ``CHAP-Password`` and
``CHAP-Challenge``. The server looks up the (hard-coded) expected
password by ``User-Name``, recomputes the digest, and returns
``Access-Accept`` on a match.

Run::

    python scenarios/auth_chap.py

Set ``PYRAD2_TRACE=1`` to dump every packet's wire bytes and decoded
AVPs.
"""

import asyncio

from loguru import logger

from _shared import (
    AUTH_PORT,
    DEMO_HOST,
    DEMO_SECRET,
    attribute_bytes,
    banner,
    make_dictionary,
    make_remote_host,
    trace_hint,
)
from pyrad2 import chap
from pyrad2.client_async import ClientAsync
from pyrad2.constants import PacketType
from pyrad2.server_async import ServerAsync

DEMO_USER = "alice"
DEMO_PASSWORD = b"clientPass"


class DemoChapServer(ServerAsync):
    def handle_auth_packet(self, protocol, pkt, addr):
        # CHAP-Password is dictionary-typed ``octets`` so it round-trips
        # as bytes natively. CHAP-Challenge is dictionary-typed
        # ``string`` per RFC 2865 §5.40 terminology — pyrad2 decodes
        # non-UTF-8 bytes there as their hex digest, so we coerce back.
        chap_password = attribute_bytes(pkt["CHAP-Password"][0])
        chap_challenge = attribute_bytes(pkt["CHAP-Challenge"][0])
        chap_id = chap_password[0]
        # Reconstruct the digest the client would have computed for the
        # expected password and compare. Any mismatch (wrong user, wrong
        # password, replayed challenge with new id) flips the verdict.
        expected = chap.build_chap_password(chap_id, DEMO_PASSWORD, chap_challenge)

        reply = self.create_reply_packet(
            pkt,
            **{"Service-Type": "Framed-User", "Framed-IP-Address": "10.0.0.42"},
        )
        if expected == chap_password:
            reply.code = PacketType.AccessAccept
            logger.info(
                "[server] CHAP digest matched for {} → Access-Accept",
                pkt["User-Name"],
            )
        else:
            reply.code = PacketType.AccessReject
            logger.warning(
                "[server] CHAP digest mismatch for {} → Access-Reject",
                pkt["User-Name"],
            )
        protocol.send_response(reply, addr)

    def handle_acct_packet(self, protocol, pkt, addr):
        pass  # required abstract, unused.


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    banner(f"Starting demo CHAP server on {DEMO_HOST}:{AUTH_PORT}")
    server = DemoChapServer(
        auth_port=AUTH_PORT,
        hosts={DEMO_HOST: make_remote_host()},
        dictionary=dictionary,
    )
    await server.initialize_transports(enable_auth=True)

    client = ClientAsync(
        server=DEMO_HOST,
        auth_port=AUTH_PORT,
        secret=DEMO_SECRET,
        dict=dictionary,
        timeout=2,
    )
    await client.initialize_transports(enable_auth=True)

    try:
        banner("Sending Access-Request authenticated via CHAP")
        req = client.create_auth_packet(User_Name=DEMO_USER)
        req["NAS-IP-Address"] = "192.168.1.10"
        # ``prepare_chap_request`` removes User-Password (if any) and
        # adds CHAP-Password + CHAP-Challenge. We pass an explicit
        # chap_id and challenge here so the log lines are reproducible
        # — production callers should let the defaults randomise both.
        chap.prepare_chap_request(
            req, DEMO_PASSWORD, chap_id=0x42, challenge=b"\xab" * 16
        )
        logger.info("[client] → Access-Request id={} (CHAP)", req.id)

        reply = await asyncio.wait_for(client.send_packet(req), timeout=2)

        banner("Reply received")
        verdict = (
            "Access-Accept"
            if reply.code == PacketType.AccessAccept
            else "Access-Reject"
        )
        logger.info("[client] ← {} id={}", verdict, reply.id)
    finally:
        await client.deinitialize_transports()
        await server.deinitialize_transports()


if __name__ == "__main__":
    asyncio.run(main())
