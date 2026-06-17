#!/usr/bin/env python
"""End-to-end EAP-MSCHAPv2 (RFC 2759) demo.

Two challenge rounds wrap the Identity bootstrap:

1. Client → ``EAP-Response/Identity`` with the user name.
2. Server → ``EAP-Request/MS-CHAPv2 Challenge`` with a random
   16-byte authenticator challenge.
3. Client → ``EAP-Response/MS-CHAPv2 Response`` with peer challenge
   + NT-Response derived from ``generate_nt_response``.
4. Server → ``EAP-Request/MS-CHAPv2 Success`` carrying the
   ``S=<auth>`` mutual-auth bytes from ``generate_authenticator_response``.
5. Client → ``EAP-Response/MS-CHAPv2 Success`` (bare 6-byte ack).
6. Server → ``Access-Accept``.

Both sides use the shared ``pyrad2.mschap`` primitives so the wire
traffic exactly matches what a real Windows NPS / FreeRADIUS deployment
emits. Requires ``pip install pyrad2[mschap]`` for the DES primitive.

Run::

    python scenarios/auth_eap_mschapv2.py
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
from pyrad2 import mschap
from pyrad2.client_async import ClientAsync
from pyrad2.constants import PacketType
from pyrad2.eap.mschapv2 import (
    EAP_TYPE_MSCHAPV2,
    OP_CHALLENGE,
    OP_RESPONSE,
    OP_SUCCESS,
)
from pyrad2.server_async import ServerAsync

DEMO_USER = "alice"
DEMO_PASSWORD = "clientPass"

EAP_TYPE_IDENTITY = 1


class DemoEapMschapV2Server(ServerAsync):
    """Server-side EAP-MSCHAPv2.

    Carries the per-session state (auth challenge, peer challenge, NT
    response, EAP id) keyed by the ``State`` cookie so the second round
    (Response → Success) finds the right context to build the
    ``S=...`` authenticator response from.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # state -> dict of {eap_id, mschap_id, auth_challenge}.
        # Stores the per-conversation context the second round needs.
        self._sessions: dict[bytes, dict] = {}

    def handle_auth_packet(self, protocol, pkt, addr):
        eap_msg = attribute_bytes(pkt["EAP-Message"][0])
        if len(eap_msg) < 5:
            return self._reject(protocol, pkt, addr, "EAP header truncated")
        eap_id = eap_msg[1]
        eap_type = eap_msg[4]

        if eap_type == EAP_TYPE_IDENTITY:
            self._send_mschap_challenge(protocol, pkt, addr, eap_id, eap_msg)
        elif eap_type == EAP_TYPE_MSCHAPV2:
            opcode = eap_msg[5] if len(eap_msg) >= 6 else 0
            if opcode == OP_RESPONSE:
                self._verify_response(protocol, pkt, addr, eap_msg)
            elif opcode == OP_SUCCESS:
                self._send_access_accept(protocol, pkt, addr)
            else:
                self._reject(protocol, pkt, addr, f"unexpected MSCHAP OpCode {opcode}")
        else:
            self._reject(protocol, pkt, addr, f"unexpected EAP-Type {eap_type}")

    def handle_acct_packet(self, protocol, pkt, addr):
        pass

    def _send_mschap_challenge(self, protocol, pkt, addr, eap_id, identity_msg):
        # Identity payload follows the 5-byte EAP header.
        identity = identity_msg[5:]
        new_eap_id = (eap_id + 1) % 256
        mschap_id = secrets.randbelow(256)
        auth_challenge = secrets.token_bytes(16)
        state = secrets.token_bytes(16)
        self._sessions[state] = {
            "eap_id": new_eap_id,
            "mschap_id": mschap_id,
            "auth_challenge": auth_challenge,
            "identity": identity,
        }
        logger.info(
            "[server] EAP-Identity '{}' → issuing MSCHAPv2 Challenge eap_id={} mschap_id={}",
            identity.decode("utf-8", errors="replace"),
            new_eap_id,
            mschap_id,
        )

        # Wire layout (draft-kamath §3.2.1):
        #   code(1)=Req | id(1) | len(2) | type(1)=26 | OpCode(1)=Challenge
        #   | mschap_id(1) | MS-Length(2) | Value-Size(1)=16
        #   | Challenge(16) | Name(variable)
        server_name = b"pyrad2-demo"
        ms_length = 1 + 1 + 2 + 1 + 16 + len(server_name)
        eap_length = 5 + ms_length
        eap_payload = (
            struct.pack(
                "!BBHBB",
                1,
                new_eap_id,
                eap_length,
                EAP_TYPE_MSCHAPV2,
                OP_CHALLENGE,
            )
            + bytes([mschap_id])
            + struct.pack("!H", ms_length)
            + bytes([16])
            + auth_challenge
            + server_name
        )
        reply = self.create_reply_packet(pkt)
        reply["EAP-Message"] = eap_payload
        reply["State"] = state
        reply.code = PacketType.AccessChallenge
        protocol.send_response(reply, addr)

    def _verify_response(self, protocol, pkt, addr, eap_msg):
        state = attribute_bytes(pkt["State"][0])
        session = self._sessions.get(state)
        if session is None:
            return self._reject(protocol, pkt, addr, "unknown State cookie")

        # Parse EAP-Response/MS-CHAPv2 Response:
        #   header(5) | OpCode(1)=2 | mschap_id(1) | MS-Length(2)
        #   | Value-Size(1)=49 | Peer-Challenge(16) | Reserved(8)
        #   | NT-Response(24) | Flags(1) | Name(variable)
        if len(eap_msg) < 59 or eap_msg[9] != 49:
            return self._reject(protocol, pkt, addr, "malformed MSCHAPv2 response")
        peer_challenge = eap_msg[10:26]
        nt_response = eap_msg[34:58]

        # Recompute the NT-Response and compare. ``challenge_hash``
        # uses the identity from EAP-Identity (not the trailing Name
        # field) per RFC 2759 §8.2.
        expected_nt = mschap.generate_nt_response(
            session["auth_challenge"],
            peer_challenge,
            session["identity"],
            DEMO_PASSWORD,
        )

        if nt_response != expected_nt:
            logger.warning("[server] NT-Response mismatch → Access-Reject")
            session_state = state
            self._sessions.pop(session_state, None)
            reply = self.create_reply_packet(pkt)
            reply.code = PacketType.AccessReject
            return protocol.send_response(reply, addr)

        # Build the S=... authenticator response — mutual auth proof.
        auth_response = mschap.generate_authenticator_response(
            DEMO_PASSWORD,
            nt_response,
            peer_challenge,
            session["auth_challenge"],
            session["identity"],
        )
        # EAP-Request/MS-CHAPv2 Success:
        #   header(5) | OpCode(1)=3 | mschap_id(1) | MS-Length(2) | Message
        new_eap_id = (eap_msg[1] + 1) % 256
        message = auth_response + b" M=Welcome"
        ms_length = 1 + 1 + 2 + len(message)
        eap_length = 5 + ms_length
        eap_payload = (
            struct.pack(
                "!BBHBB",
                1,
                new_eap_id,
                eap_length,
                EAP_TYPE_MSCHAPV2,
                OP_SUCCESS,
            )
            + bytes([session["mschap_id"]])
            + struct.pack("!H", ms_length)
            + message
        )
        logger.info(
            "[server] NT-Response matched → issuing MSCHAPv2 Success eap_id={}",
            new_eap_id,
        )
        # Carry the same State across so the client's Success-Response
        # finds its way back to the right session entry.
        reply = self.create_reply_packet(pkt)
        reply["EAP-Message"] = eap_payload
        reply["State"] = state
        reply.code = PacketType.AccessChallenge
        protocol.send_response(reply, addr)

    def _send_access_accept(self, protocol, pkt, addr):
        state = attribute_bytes(pkt["State"][0])
        self._sessions.pop(state, None)
        logger.info("[server] Client ACK'd Success → Access-Accept")
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.AccessAccept
        protocol.send_response(reply, addr)

    def _reject(self, protocol, pkt, addr, reason):
        logger.warning("[server] rejecting: {}", reason)
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.AccessReject
        protocol.send_response(reply, addr)


async def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    banner(f"Starting demo EAP-MSCHAPv2 server on {DEMO_HOST}:{AUTH_PORT}")
    server = DemoEapMschapV2Server(
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
        banner("Sending EAP-MSCHAPv2 Access-Request")
        req = client.create_auth_packet(
            User_Name=DEMO_USER, User_Password=DEMO_PASSWORD
        )
        req["NAS-IP-Address"] = "192.168.1.10"
        req.auth_type = "eap-mschapv2"
        logger.info("[client] → Access-Request id={} (EAP-MSCHAPv2)", req.id)

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
