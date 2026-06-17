#!/usr/bin/env python
"""End-to-end EAP-GTC (Generic Token Card, RFC 3748 §5.6) demo.

A one-round-trip exchange after the Identity bootstrap:

1. Client → ``Access-Request`` carrying ``EAP-Response/Identity``.
2. Server → ``Access-Challenge`` carrying ``EAP-Request/GTC`` with a
   display prompt and a ``State`` cookie.
3. Client → ``Access-Request`` carrying ``EAP-Response/GTC`` with
   the user's password (clear text — see security note below).
4. Server compares against the known password and replies.

EAP-GTC ships the password in clear text over the EAP-Message AVP;
production deployments almost always wrap it inside an EAP-PEAP /
EAP-TTLS TLS tunnel. This demo runs it standalone purely to exercise
the ``GtcMethod`` driver. **Do not use unwrapped GTC in production.**

Run::

    python scenarios/auth_eap_gtc.py
"""

import asyncio
import secrets
import struct

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
from pyrad2.client_async import ClientAsync
from pyrad2.constants import PacketType
from pyrad2.server_async import ServerAsync

DEMO_USER = "alice"
DEMO_PASSWORD = b"clientPass"

EAP_TYPE_IDENTITY = 1
EAP_TYPE_GTC = 6


class DemoEapGtcServer(ServerAsync):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # state → eap_id we issued the GTC challenge with.
        self._sessions: dict[bytes, int] = {}

    def handle_auth_packet(self, protocol, pkt, addr):
        eap_msg = attribute_bytes(pkt["EAP-Message"][0])
        if len(eap_msg) < 5:
            return self._reject(protocol, pkt, addr, "EAP header truncated")
        eap_id = eap_msg[1]
        eap_type = eap_msg[4]

        if eap_type == EAP_TYPE_IDENTITY:
            self._send_gtc_prompt(protocol, pkt, addr, eap_id)
        elif eap_type == EAP_TYPE_GTC:
            self._verify_gtc_response(protocol, pkt, addr, eap_msg)
        else:
            self._reject(protocol, pkt, addr, f"unexpected EAP-Type {eap_type}")

    def handle_acct_packet(self, protocol, pkt, addr):
        pass

    def _send_gtc_prompt(self, protocol, pkt, addr, eap_id):
        new_eap_id = (eap_id + 1) % 256
        state = secrets.token_bytes(16)
        self._sessions[state] = new_eap_id
        # EAP-Request/GTC: code(1) + id(1) + length(2) + type(1) + prompt
        prompt = b"Password: "
        eap_payload = (
            struct.pack("!BBHB", 1, new_eap_id, 5 + len(prompt), EAP_TYPE_GTC) + prompt
        )
        logger.info(
            "[server] EAP-Identity from {} → issuing GTC prompt id={}",
            pkt["User-Name"],
            new_eap_id,
        )
        reply = self.create_reply_packet(pkt)
        reply["EAP-Message"] = eap_payload
        reply["State"] = state
        reply.code = PacketType.AccessChallenge
        protocol.send_response(reply, addr)

    def _verify_gtc_response(self, protocol, pkt, addr, eap_msg):
        state = attribute_bytes(pkt["State"][0])
        if self._sessions.pop(state, None) is None:
            return self._reject(protocol, pkt, addr, "unknown State cookie")
        # EAP-Response/GTC body is everything after the 5-byte EAP header.
        received_password = eap_msg[5:]
        reply = self.create_reply_packet(pkt)
        if received_password == DEMO_PASSWORD:
            reply.code = PacketType.AccessAccept
            logger.info("[server] GTC password matched → Access-Accept")
        else:
            reply.code = PacketType.AccessReject
            logger.warning("[server] GTC password mismatch → Access-Reject")
        protocol.send_response(reply, addr)

    def _reject(self, protocol, pkt, addr, reason):
        logger.warning("[server] rejecting: {}", reason)
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.AccessReject
        protocol.send_response(reply, addr)


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    banner(f"Starting demo EAP-GTC server on {DEMO_HOST}:{AUTH_PORT}")
    server = DemoEapGtcServer(
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
        banner("Sending EAP-GTC Access-Request")
        req = client.create_auth_packet(
            User_Name=DEMO_USER, User_Password=DEMO_PASSWORD.decode()
        )
        req["NAS-IP-Address"] = "192.168.1.10"
        req.auth_type = "eap-gtc"
        logger.info("[client] → Access-Request id={} (EAP-GTC)", req.id)

        reply = await asyncio.wait_for(client.send_packet(req), timeout=4)

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
