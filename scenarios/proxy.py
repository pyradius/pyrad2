#!/usr/bin/env python
"""End-to-end RADIUS proxy demo.

Wires up three roles in one process to exercise the full proxy data
flow:

- An **upstream** ``Server`` on ``UPSTREAM_PORT`` that answers
  Access-Request with Access-Accept.
- A **proxy** ``Proxy`` on ``PROXY_PORT`` that forwards each
  Access-Request to the upstream via its dedicated reply socket
  (``Proxy._proxyfd``) and relays the reply back to the originating
  client.
- A **downstream** sync ``Client`` that sends a single Access-Request to
  the proxy and waits for the reply.

The proxy and upstream each run in their own daemon thread; the main
thread drives the client. Setting ``PYRAD2_TRACE=1`` (plus
``PYRAD2_TRACE_UNSAFE=1``) shows every packet on the wire as it crosses
the loopback.

Run::

    python scenarios/proxy.py
"""

import socket
import threading
import time

from loguru import logger

from _shared import (
    DEMO_HOST,
    DEMO_SECRET,
    banner,
    make_dictionary,
    trace_hint,
)
from pyrad2.client import Client
from pyrad2.constants import PacketType
from pyrad2.proxy import Proxy
from pyrad2.server import RemoteHost, Server

PROXY_PORT = 11820
UPSTREAM_PORT = 11821


class DemoUpstream(Server):
    """Trivial RADIUS server: every Access-Request becomes Access-Accept."""

    def handle_auth_packet(self, pkt):
        logger.info(
            "[upstream] Access-Request id={} from {} user-name={}",
            pkt.id,
            pkt.source,
            pkt["User-Name"],
        )
        reply = self.create_reply_packet(
            pkt,
            **{
                "Service-Type": "Framed-User",
                "Framed-IP-Address": "10.0.0.42",
            },
        )
        reply.code = PacketType.AccessAccept
        logger.info("[upstream] → Access-Accept id={}", pkt.id)
        self.send_reply_packet(pkt.fd, reply)


class DemoProxy(Proxy):
    """Verbatim Access-Request forwarder.

    The demo reuses a single shared secret across all hops so the
    upstream's Response Authenticator stays valid when the bytes are
    relayed back to the client without re-MAC'ing. A production proxy
    would rewrite the request id, generate a fresh Request Authenticator
    per upstream send, and recompute the response MAC with the
    downstream's secret.
    """

    def __init__(self, *args, upstream_addr, **kwargs):
        super().__init__(*args, **kwargs)
        self._upstream_addr = upstream_addr
        # id → (downstream_addr, downstream_fd) so the reply path on
        # ``_proxyfd`` knows which client to mirror back to.
        self._pending: dict[int, tuple] = {}

    def handle_auth_packet(self, pkt):
        logger.info(
            "[proxy] Access-Request id={} from {} → upstream {}:{}",
            pkt.id,
            pkt.source,
            self._upstream_addr[0],
            self._upstream_addr[1],
        )
        self._pending[pkt.id] = (pkt.source, pkt.fd)
        self._proxyfd.sendto(pkt.request_packet(), self._upstream_addr)

    def _handle_proxy_packet(self, pkt):
        # Run the base validation (source in hosts, code is a response)
        # then forward to whoever originated the request.
        super()._handle_proxy_packet(pkt)
        route = self._pending.pop(pkt.id, None)
        if route is None:
            logger.warning("[proxy] reply id={} has no pending route", pkt.id)
            return
        downstream_addr, downstream_fd = route
        logger.info(
            "[proxy] ← {} id={} from upstream — forwarding to {}",
            PacketType(pkt.code).name,
            pkt.id,
            downstream_addr,
        )
        # Bytes are forwarded verbatim. ``recv_buf`` was captured by
        # ``parse_packet`` on the way in; the wire form is identical
        # because the shared secret is the same across hops.
        downstream_fd.sendto(pkt.raw_packet, downstream_addr)


def _wait_for_port(host: str, port: int, timeout: float = 2.0) -> None:
    """Block until a UDP listener responds on (host, port).

    We poke the socket with an empty datagram and rely on the server
    being able to ``recvfrom`` it once bound. Cheaper than a real
    handshake and good enough for a single-process demo.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect((host, port))
            return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError(f"{host}:{port} did not come up within {timeout}s")


def main() -> None:
    trace_hint()
    dictionary = make_dictionary()

    upstream_hosts = {
        DEMO_HOST: RemoteHost(DEMO_HOST, DEMO_SECRET, "proxy-as-client"),
    }
    proxy_hosts = {
        DEMO_HOST: RemoteHost(DEMO_HOST, DEMO_SECRET, "downstream-and-upstream"),
    }

    banner(f"Starting upstream server on {DEMO_HOST}:{UPSTREAM_PORT}")
    upstream = DemoUpstream(
        addresses=[DEMO_HOST],
        authport=UPSTREAM_PORT,
        acctport=UPSTREAM_PORT + 1,
        hosts=upstream_hosts,
        dict=dictionary,
        acct_enabled=False,
    )
    upstream_thread = threading.Thread(target=upstream.run, daemon=True)
    upstream_thread.start()

    banner(f"Starting proxy on {DEMO_HOST}:{PROXY_PORT}")
    proxy = DemoProxy(
        addresses=[DEMO_HOST],
        authport=PROXY_PORT,
        acctport=PROXY_PORT + 1,
        hosts=proxy_hosts,
        dict=dictionary,
        acct_enabled=False,
        upstream_addr=(DEMO_HOST, UPSTREAM_PORT),
    )
    proxy_thread = threading.Thread(target=proxy.run, daemon=True)
    proxy_thread.start()

    _wait_for_port(DEMO_HOST, UPSTREAM_PORT)
    _wait_for_port(DEMO_HOST, PROXY_PORT)

    banner("Sending Access-Request to the proxy")
    client = Client(
        server=DEMO_HOST,
        authport=PROXY_PORT,
        secret=DEMO_SECRET,
        dict=dictionary,
        timeout=2,
        retries=1,
    )
    req = client.create_auth_packet(User_Name="alice")
    req["NAS-IP-Address"] = "192.168.1.10"
    req["Service-Type"] = "Login-User"
    logger.info("[client] → Access-Request id={} user-name=alice", req.id)

    reply = client.send_packet(req)

    banner("Reply received")
    verdict = (
        "Access-Accept" if reply.code == PacketType.AccessAccept else "Access-Reject"
    )
    logger.info("[client] ← {} id={}", verdict, reply.id)
    for key in reply.keys():
        logger.info("[client]   {}: {}", key, reply[key])


if __name__ == "__main__":
    main()
