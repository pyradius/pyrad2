# Running a RADIUS Server

pyrad2 servers are libraries you subclass - pyrad2 handles packet parsing, transport, retransmission, and replies, and you implement the business logic.

This page builds up from a minimal server to RadSec and RADIUS/1.1, in that order.

## Your first server

A server is one class with two handler methods. Save this as `server.py`:

```python
import asyncio
from pyrad2.server_async import ServerAsync
from pyrad2.dictionary import Dictionary
from pyrad2.host import RemoteHost
from pyrad2.constants import PacketType


class MyServer(ServerAsync):
    def handle_auth_packet(self, protocol, pkt, addr):
        reply = self.create_reply_packet(pkt, **{"Service-Type": "Framed-User"})
        reply.code = PacketType.AccessAccept
        protocol.send_response(reply, addr)

    def handle_acct_packet(self, protocol, pkt, addr):
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.AccountingResponse
        protocol.send_response(reply, addr)


async def main():
    server = MyServer(
        hosts={"127.0.0.1": RemoteHost("127.0.0.1", b"my-secret", "localhost")},
        dictionary=Dictionary("dictionary"),
    )
    await server.initialize_transports(enable_auth=True, enable_acct=True)
    try:
        await asyncio.Event().wait()
    finally:
        await server.deinitialize_transports()


asyncio.run(main())
```

Run it:

```bash
uv run server.py
```

You should see:

```
[127.0.0.1:1812] Transport created
[127.0.0.1:1813] Transport created
```

That's a working RADIUS server. The next sections explain what's happening and how to make it useful.

!!! tip "Sync or async?"

    The example above is async - recommended for new code. A synchronous `Server` class exists in `pyrad2.server` for legacy compatibility, but sync support **may be dropped in a future release**. Use [`server_async.py`](https://github.com/nicholasamorim/pyrad2/blob/master/examples/server_async.py) as your starting template.

## Handling requests

Every handler receives:

| Argument | What it is |
| --- | --- |
| `protocol` | The transport - call `protocol.send_response(reply, addr)` to reply |
| `pkt` | A parsed [`Packet`](api/packet.md) - already validated and decoded |
| `addr` | The source `(host, port)` tuple |

`pkt` behaves like a dict of attributes. Iterate it, look up values, log it - whatever your logic needs:

```python
def handle_auth_packet(self, protocol, pkt, addr):
    logger.info("Auth request id={} from {}", pkt.id, addr)
    for name, values in pkt.items():
        logger.info("  {}: {}", name, values)
```

## Sending replies

Every reply starts with `self.create_reply_packet(request, **attributes)`, then sets the response code, then goes out via the protocol:

```python
def handle_auth_packet(self, protocol, pkt, addr):
    reply = self.create_reply_packet(
        pkt,
        **{
            "Service-Type": "Framed-User",
            "Framed-IP-Address": "192.168.0.1",
            "Framed-IPv6-Prefix": "fc66::1/64",
        },
    )
    reply.code = PacketType.AccessAccept
    protocol.send_response(reply, addr)
```

### Reply codes

Reply codes live on the [`PacketType`](api/constants.md) enum:

| Code | Use |
| --- | --- |
| `PacketType.AccessAccept` | Auth succeeded |
| `PacketType.AccessReject` | Auth failed |
| `PacketType.AccessChallenge` | Need more info (EAP, RADIUS challenge) |
| `PacketType.AccountingResponse` | Acknowledge an accounting record |
| `PacketType.CoAACK` / `CoANAK` | Accept/reject a CoA-Request |
| `PacketType.DisconnectACK` / `DisconnectNAK` | Accept/reject a Disconnect-Request |

See the [constants reference](api/constants.md) for the complete list.

## Dynamic authorization (CoA & Disconnect)

CoA and Disconnect are part of [RFC 5176](https://datatracker.ietf.org/doc/html/rfc5176). They flow *from* a Dynamic Authorization Server *to* a NAS to **change** or **terminate** an active session - the opposite direction from normal auth requests.

You only need these handlers if your server is acting as a NAS or proxy and accepts CoA/Disconnect requests. Enable the listener with `enable_coa=True` and override the handlers:

```python
class MyDynAuthServer(ServerAsync):
    def handle_coa_packet(self, protocol, pkt, addr):
        # apply session change ...
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.CoAACK
        protocol.send_response(reply, addr)

    def handle_disconnect_packet(self, protocol, pkt, addr):
        # tear down session ...
        reply = self.create_reply_packet(pkt)
        reply.code = PacketType.DisconnectACK
        protocol.send_response(reply, addr)
```

If you **don't** override them, pyrad2 responds with `CoA-NAK` / `Disconnect-NAK` and `Error-Cause = Unsupported-Extension`. That's the correct, clean default - you never have to write a stub just to be polite.

## Status-Server health checks

[RFC 5997](https://datatracker.ietf.org/doc/html/rfc5997) Status-Server requests are handled **before** they reach your auth/acct handlers - no extra code required.

| Arrives on | Response |
| --- | --- |
| Auth port (1812) | `Access-Accept` |
| Accounting port (1813) | `Accounting-Response` |

Status-Server requests **must** include a valid `Message-Authenticator`; requests without one are dropped. Your handlers are not called, so health checks never run authentication side effects.

## Duplicate detection (RFC 5080)

UDP loses packets. Clients retransmit. [RFC 5080 §2.2.2](https://datatracker.ietf.org/doc/html/rfc5080#section-2.2.2) requires servers to **detect duplicates and resend the original reply** instead of re-running the handler.

This matters most for **EAP**: each `Access-Challenge` carries a fresh `State` attribute, and re-processing a retransmission would mint a new `State` that breaks the conversation. It also matters for **accounting** (no double-counts) and **CoA/Disconnect** (no double-applying authorization changes).

Both `Server` and `ServerAsync` enable it by default. The cache key is the RFC-mandated tuple `(source IP, source UDP port, code, Identifier, Request Authenticator)`. Retransmissions of:

- `Access-Request`
- `Accounting-Request`
- `CoA-Request`
- `Disconnect-Request`

receive the **byte-identical** cached reply for `dedup_ttl` seconds. Your handler runs exactly once. Duplicates that arrive while the original is still being processed are dropped silently.

### Tuning

```python
server = ServerAsync(
    # ...
    dedup_enabled=True,      # default
    dedup_ttl=30.0,          # seconds a cached reply stays valid
    dedup_max_entries=4096,  # LRU cap before old entries get evicted
)
```

Pass `dedup_enabled=False` to opt out, or `dedup_cache=...` (a `pyrad2.dedup.ResponseCache` instance) to share one cache across servers or inject a custom clock for tests.

Status-Server requests, CoA/Disconnect-NAK replies, and packets where the parsed source doesn't match an allowed `RemoteHost` are never cached.

!!! note "RadSec is exempt"

    RadSec runs over TCP/TLS, where the transport handles retransmission of lost segments. The dedup cache is not wired into `RadSecServer`.

## Message-Authenticator

pyrad2 validates `Message-Authenticator` whenever it's present and, by default, requires it on every incoming `Access-Request`. This mitigates [BlastRADIUS (CVE-2024-3596)](https://www.blastradius.fail/) out of the box — an off-path attacker who can spoof source IP can no longer forge an `Access-Accept`.

Scope of the default (`require_message_authenticator=True`):

- **`Access-Request` must include a valid `Message-Authenticator`** — incoming packets without one are dropped before reaching your handler.
- **Access replies (`Access-Accept` / `Reject` / `Challenge`) automatically get `Message-Authenticator`** before they go on the wire.
- **`Accounting-Request`, `CoA-Request`, `Disconnect-Request` (and their replies) are unaffected** — those codes carry a Request/Response Authenticator MD5 over the body and shared secret, so the body is already integrity-protected.
- **Packets with `EAP-Message` must include a valid `Message-Authenticator`** (RFC 3579 §3.2).
- **`Status-Server` must include a valid `Message-Authenticator`** (RFC 5997 §3) — independent of the flag.

To bridge a legacy NAS that doesn't emit the attribute, set `require_message_authenticator=False` when constructing `Server` or `ServerAsync`. `RadSecServer` defaults to `False` because TLS already authenticates origin and integrity (off-path forgery is impossible by construction); flip it to `True` only if you need strict parity with UDP deployments.

## RadSec - RADIUS over TLS

!!! info "Status"

    Experimental. Implements [RFC 6614](https://datatracker.ietf.org/doc/html/rfc6614).

RadSec is RADIUS over TLS/TCP instead of UDP. It replaces the MD5-based packet authentication that has aged poorly with proper TLS, and uses port **2083** for everything - auth, accounting, and dynamic authorization all share one mutually-authenticated connection.

The shared secret defaults to `radsec` per the RFC, but you can override it per host.

### A minimal RadSec server

```python
import os, asyncio
from pyrad2.radsec.server import RadSecServer as BaseRadSecServer
from pyrad2.dictionary import Dictionary
from pyrad2.host import RemoteHost
from pyrad2.constants import PacketType


class RadSecServer(BaseRadSecServer):
    async def handle_access_request(self, packet):
        reply = packet.create_reply()
        reply.code = PacketType.AccessAccept
        return reply

    async def handle_accounting(self, packet):
        reply = packet.create_reply()
        reply.code = PacketType.AccountingResponse
        return reply

    # Optional - override only when acting as a Dynamic Authorization Server.
    # Default behavior is CoA-NAK / Disconnect-NAK with Error-Cause.
    # async def handle_coa(self, packet): ...
    # async def handle_disconnect(self, packet): ...


async def main():
    here = os.path.dirname(os.path.abspath(__file__))
    server = RadSecServer(
        hosts={"127.0.0.1": RemoteHost("127.0.0.1", b"radsec", "localhost")},
        dictionary=Dictionary(f"{here}/dictionary"),
        certfile=f"{here}/certs/server/server.cert.pem",
        keyfile=f"{here}/certs/server/server.key.pem",
        ca_certfile=f"{here}/certs/ca/ca.cert.pem",
    )
    await server.run()


asyncio.run(main())
```

When the server is ready you'll see:

```
RADSEC Server with mutual TLS running on ('0.0.0.0', 2083)
```

A full example lives in [`examples/server_radsec.py`](https://github.com/nicholasamorim/pyrad2/blob/master/examples/server_radsec.py). Test certificates ship in [`examples/certs/`](https://github.com/nicholasamorim/pyrad2/blob/master/examples/certs/).

!!! note "Async only"

    There is no sync RadSec server.

### Health-checking a RadSec server

Status-Server health checks reuse the same TLS/TCP connection as everything else. Use [`examples/status_radsec.py`](https://github.com/nicholasamorim/pyrad2/blob/master/examples/status_radsec.py) - the UDP `status.py` script can't reach a RadSec server.


## RADIUS/1.1 (RFC 9765)

!!! warning "Status"

    Experimental. [RFC 9765](https://datatracker.ietf.org/doc/html/rfc9765) was published in April 2025 and ecosystem support is still small.

RADIUS/1.1 is a **TLS-only profile** of RADIUS that drops the MD5 baggage now that TLS already provides authentication, integrity, and confidentiality. Both versions share the same RadSec port (2083); the protocol version is negotiated via **TLS ALPN**.

| ALPN string | Profile |
| --- | --- |
| `radius/1.0` | Historic RADIUS, MD5-based ([RFC 2865](https://datatracker.ietf.org/doc/html/rfc2865)) |
| `radius/1.1` | RFC 9765 - no MD5, no Message-Authenticator, Token instead of Request Authenticator |

### What changes in v1.1

| Area | Behavior |
| --- | --- |
| `User-Password`, `Tunnel-Password`, `MS-MPPE-*-Key` | **Plain text** - TLS authenticated the bytes (§5.1.1, §5.1.3, §5.1.4) |
| `Message-Authenticator` | **Forbidden** to send; silently discarded if received (§5.2) |
| Request Authenticator | Replaced by a 32-bit per-connection **Token**; remaining 12 bytes zero (§4.1) |
| Identifier byte | Zero on the wire - matching uses the Token (§4.1) |
| MD5 verifiers | All short-circuit - TLS already authenticated the bytes |

In your auth handler, `packet["User-Password"]` is the literal cleartext bytes the client sent.

### Enabling v1.1

Pass `radius_versions=...` to the server constructor. The default is `(V1_0,)` for backward compatibility - no ALPN string is advertised, so historic peers see byte-identical TLS handshakes.

```python
from pyrad2.radsec.v11 import RadiusVersion

server = RadSecServer(
    # ...
    radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1),
)
```

### Negotiation outcomes

| Server advertises | Client advertises | Result |
| --- | --- | --- |
| `(V1_0,)` | `(V1_0,)` | v1.0 (no ALPN sent - identical to historic RadSec) |
| `(V1_0, V1_1)` | `(V1_0, V1_1)` | **v1.1** - highest mutually supported wins |
| `(V1_0,)` | `(V1_0, V1_1)` | v1.0 (server silent on ALPN, client falls back) |
| `(V1_0, V1_1)` | `(V1_0,)` | v1.0 (client silent on ALPN, server falls back) |
| `(V1_1,)` | `(V1_0,)` | **Connection closed** - server refuses to downgrade (§3.3) |
| `(V1_0,)` | `(V1_1,)` | Client raises `PacketError` and the call returns `None` |
| `(V1_1,)` | `(V1_1,)` | v1.1 |

A connection is rejected exactly when one side is configured *only* for v1.1 and the other side doesn't advertise the `radius/1.1` ALPN.

**TLS 1.3 is the default for RadSec** on both sides ([RFC 9325](https://datatracker.ietf.org/doc/html/rfc9325) deprecates 1.1 and below and treats 1.2 as legacy). RFC 9765 §3.4 additionally mandates **TLS 1.3 or later** whenever v1.1 is in play, and `RadSecServer` / `RadSecClient` auto-promote `minimum_tls_version` to `TLSv1_3` when v1.1 is configured. To bridge a legacy peer that can't yet negotiate 1.3 on a pure v1.0 deployment, pin the floor down explicitly:

```python
import ssl
RadSecServer(..., minimum_tls_version=ssl.TLSVersion.TLSv1_2)
```

The negotiated version is available on every parsed packet as `packet.radius_version`. The RadSec server logs `RADSEC connection established from ... (ALPN=..., RADIUS/...)` on every handshake.

### Writing a v1.1-aware handler

Most handlers work unchanged. The only practical difference is the `User-Password` access pattern: in v1.1 it's already plaintext; in v1.0 you decrypt it as before.

```python
async def handle_access_request(self, packet):
    if packet.radius_version == RadiusVersion.V1_1:
        password = packet["User-Password"][0]          # plain string
    else:
        password = packet.pw_decrypt(packet[2][0])     # raw bytes → str

    reply = packet.create_reply()
    reply.code = PacketType.AccessAccept
    return reply
```

The reply path is fully automatic: `create_reply()` propagates `radius_version` and the Token; `reply_packet()` skips MD5 / Message-Authenticator when v1.1 is set.
