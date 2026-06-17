#!/usr/bin/env python
"""End-to-end EAP-MD5 challenge/response demo (RFC 3748 §5.4).

Three on-the-wire messages exchange three EAP packets:

1. Client → Access-Request carrying ``EAP-Response/Identity``.
2. Server → Access-Challenge carrying ``EAP-Request/MD5-Challenge``
   with a fresh 16-byte challenge plus a ``State`` cookie.
3. Client → Access-Request carrying ``EAP-Response/MD5-Challenge``
   with ``MD5(eap_id || password || challenge)`` and the same ``State``.
4. Server verifies the digest against the known password and replies
   ``Access-Accept`` or ``Access-Reject``.

The client side is one line: ``req.auth_type = "eap-md5"``. The
client-loop refactor introduced in Stage 1 then calls the registered
``Md5Method`` to handle ``inject_eap_identity`` and
``apply_eap_md5_challenge`` automatically.

Run::

    python scenarios/auth_eap_md5.py
"""

import asyncio
import hashlib
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
EAP_TYPE_MD5 = 4


class DemoEapMd5Server(ServerAsync):
    """Server side of the RFC 3748 §5.4 challenge/response.

    Stores the per-conversation challenge keyed by the ``State`` cookie
    we hand back to the client; receiving that ``State`` on the second
    Access-Request lets us look up the exact challenge we issued.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sessions: dict[bytes, tuple[int, bytes]] = {}

    def handle_auth_packet(self, protocol, pkt, addr):
        # EAP-Message is dictionary-typed ``string``; coerce back to
        # the raw bytes the EAP framing actually uses.
        eap_msg = attribute_bytes(pkt["EAP-Message"][0])
        if len(eap_msg) < 5:
            return self._reject(protocol, pkt, addr, "EAP header truncated")

        eap_id = eap_msg[1]
        eap_type = eap_msg[4]

        if eap_type == EAP_TYPE_IDENTITY:
            self._send_md5_challenge(protocol, pkt, addr, eap_id)
        elif eap_type == EAP_TYPE_MD5:
            self._verify_md5_response(protocol, pkt, addr, eap_id, eap_msg)
        else:
            self._reject(protocol, pkt, addr, f"unexpected EAP-Type {eap_type}")

    def handle_acct_packet(self, protocol, pkt, addr):
        pass

    def _send_md5_challenge(self, protocol, pkt, addr, eap_id):
        challenge = secrets.token_bytes(16)
        # RFC 3748 §4.1 — Identifier must change between Requests we send.
        # Cycle past whatever the client used.
        new_eap_id = (eap_id + 1) % 256
        state = secrets.token_bytes(16)
        self._sessions[state] = (new_eap_id, challenge)
        logger.info(
            "[server] EAP-Identity from {} → issuing MD5-Challenge id={} state={}",
            pkt["User-Name"],
            new_eap_id,
            state.hex()[:8],
        )

        # EAP-Request/MD5-Challenge wire layout:
        #   code(1) + id(1) + length(2) + type(1) + size(1) + challenge(N) + name?
        # We omit Name; the demo doesn't carry an EAP server name.
        eap_payload = (
            struct.pack(
                "!BBHBB",
                1,
                new_eap_id,
                6 + len(challenge),
                EAP_TYPE_MD5,
                len(challenge),
            )
            + challenge
        )
        reply = self.create_reply_packet(pkt)
        reply["EAP-Message"] = eap_payload
        reply["State"] = state
        reply.code = PacketType.AccessChallenge
        protocol.send_response(reply, addr)

    def _verify_md5_response(self, protocol, pkt, addr, eap_id, eap_msg):
        state = attribute_bytes(pkt["State"][0])
        session = self._sessions.pop(state, None)
        if session is None:
            return self._reject(protocol, pkt, addr, "unknown State cookie")
        expected_eap_id, challenge = session

        # EAP-Response/MD5-Challenge layout:
        #   code(1) + id(1) + length(2) + type(1) + size(1) + digest(16)
        if len(eap_msg) < 22 or eap_msg[5] != 16:
            return self._reject(protocol, pkt, addr, "malformed MD5 response")
        received_eap_id = eap_msg[1]
        received = eap_msg[6:22]
        expected = hashlib.md5(
            bytes([received_eap_id]) + DEMO_PASSWORD + challenge
        ).digest()

        reply = self.create_reply_packet(pkt)
        if received == expected:
            reply.code = PacketType.AccessAccept
            logger.info(
                "[server] MD5 digest matched for eap_id={} → Access-Accept",
                received_eap_id,
            )
        else:
            reply.code = PacketType.AccessReject
            logger.warning("[server] MD5 digest mismatch → Access-Reject")
        protocol.send_response(reply, addr)

    def _reject(self, protocol, pkt, addr, reason):
        logger.warning("[server] rejecting: {}", reason)
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.AccessReject
        protocol.send_response(reply, addr)


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    banner(f"Starting demo EAP-MD5 server on {DEMO_HOST}:{AUTH_PORT}")
    server = DemoEapMd5Server(
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
        banner("Sending EAP-MD5 Access-Request")
        req = client.create_auth_packet(
            User_Name=DEMO_USER, User_Password=DEMO_PASSWORD.decode()
        )
        req["NAS-IP-Address"] = "192.168.1.10"
        # One line picks the EAP method — the client loop dispatches
        # ``Md5Method.start`` before the first send and
        # ``Md5Method.respond`` after the Access-Challenge automatically.
        req.auth_type = "eap-md5"
        logger.info("[client] → Access-Request id={} (EAP-MD5)", req.id)

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
