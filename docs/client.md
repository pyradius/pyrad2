# Making RADIUS Requests

The client side of pyrad2 builds packets, sends them, handles retransmission and timeouts, and returns parsed responses. This page goes from a basic auth request to EAP, health checks, RadSec, and RADIUS/1.1.

## Your first request

There are two client classes: `ClientAsync` (recommended) in `pyrad2.client_async`, and a sync `Client` in `pyrad2.client`. They share the same API surface.

```python
from pyrad2.client_async import ClientAsync
from pyrad2.dictionary import Dictionary
from pyrad2.constants import PacketType


client = ClientAsync(
    server="localhost",
    secret=b"Kah3choteereethiejeimaeziecumi",
    timeout=4,
    dict=Dictionary("dictionary"),
)

await client.initialize_transports(enable_auth=True)

req = client.create_auth_packet(User_Name="alice")
req["NAS-IP-Address"] = "192.168.1.10"
req["Service-Type"] = "Login-User"

reply = await client.send_packet(req)

if reply.code == PacketType.AccessAccept:
    print("Access accepted")
    for name, values in reply.items():
        print(f"  {name}: {values}")
```

That's the whole loop: build, send, inspect.

A complete runnable version with logging and error handling lives in [`examples/auth_async.py`](https://github.com/pyradius/pyrad2/blob/master/examples/auth_async.py).

!!! warning "Same dictionary on both sides"

    Your client and server must load **compatible dictionaries**. They are how each side agrees on what attribute code `1` means.

!!! note "Don't hardcode secrets"

    The examples on this page use literal secrets for clarity. In real code, load them from your config or secrets manager.

## Setting attributes

There are two ways to set attributes, and they look slightly different:

| Style | Use case |
| --- | --- |
| `create_auth_packet(User_Name="alice")` | Constructor kwargs - **underscores** because Python identifiers can't contain hyphens |
| `req["User-Name"] = "alice"` | Dict-style access - **hyphens**, matches the wire-name |

Both produce the same packet. Use whichever reads better in context.

```python
req = client.create_auth_packet(User_Name="alice")
req["NAS-IP-Address"] = "192.168.1.10"
req["NAS-Port"] = 0
req["Service-Type"] = "Login-User"
req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
req["Framed-IP-Address"] = "10.0.0.100"
```

A list of standard RADIUS attributes lives in [RFC 2865 §5](https://datatracker.ietf.org/doc/html/rfc2865#section-5). Vendor-specific attributes come from your vendor dictionary.

## Authentication methods

PAP (cleartext `User-Password`) is the default. For CHAP, EAP-MD5,
EAP-GTC, MS-CHAPv2, and EAP-MSCHAPv2, see the dedicated
[Authentication Methods](auth.md) page. The shortest version: set
`req.auth_type = "eap-md5"` (or `"eap-gtc"`, `"eap-mschapv2"`) and the
client loop drives the challenge exchange automatically. MS-CHAPv2 /
EAP-MSCHAPv2 need an optional dependency — `pip install pyrad2[mschap]`.

```python
req = client.create_auth_packet(
    User_Name="alice",
    User_Password="hunter2",
    auth_type="eap-md5",
)
reply = await client.send_packet(req)
```

Under the hood, the client looks up the method via `pyrad2.eap.get_method(pkt.auth_type)` and drives it through a transport-neutral challenge loop. Registering a new method is a one-call addition:

```python
from pyrad2.eap import EapMethod, register_method

class FooMethod(EapMethod):
    def start(self, pkt): ...
    def respond(self, pkt, challenge): ...

register_method("eap-foo", FooMethod)
```

Callers then set `req.auth_type = "eap-foo"` and the existing client loop drives `start` before the first send and `respond` after every `Access-Challenge` until the server returns `Access-Accept` / `Access-Reject`.

## Retries and backoff

`Client` and `ClientAsync` share a `RetryPolicy` (`pyrad2.retry.RetryPolicy`) covering how many retransmissions to attempt, the base wait, exponential backoff, jitter, and a hard cap. The legacy `retries=` / `timeout=` kwargs still work — they build a flat-schedule policy under the hood:

```python
ClientAsync(server="...", retries=3, timeout=5)
# equivalent to:
ClientAsync(
    server="...",
    retry_policy=RetryPolicy(retries=3, timeout=5.0),
)
```

For backoff or jitter, pass an explicit `retry_policy`:

```python
from pyrad2.retry import RetryPolicy
from pyrad2.client_async import ClientAsync

client = ClientAsync(
    server="radius.example.com",
    secret=b"...",
    dict=dictionary,
    retry_policy=RetryPolicy(
        retries=4,
        timeout=2.0,
        backoff=2.0,    # 2s, 4s, 8s, 16s
        jitter=0.1,     # ±10% noise per wait — avoids lockstep retries
        max_wait=30.0,  # cap any single wait at 30s
    ),
)
```

The async timeout handler consults `wait_for(attempt)` per pending request, so backoff applies to each retry independently. On the sync side, `Acct-Delay-Time` is bumped by the *actual* wait of the previous attempt (not the base timeout), so accounting requests stay correct under backoff.

## Message-Authenticator

By default (`enforce_ma=True`) pyrad2 stamps `Message-Authenticator` onto every outgoing `Access-Request` and refuses any `Access-Accept` / `Reject` / `Challenge` reply that doesn't carry one. This mitigates [BlastRADIUS (CVE-2024-3596)](https://www.blastradius.fail/) without any extra wiring on your side.

Scope of the default:

- `Access-Request` gets `Message-Authenticator` added before send; the matching `Access-*` reply is required to carry one too.
- Replies to `Accounting-Request`, `CoA-Request`, and `Disconnect-Request` aren't required to include `Message-Authenticator` — their Response Authenticator MD5 already authenticates the body and shared secret.
- `Status-Server` (RFC 5997) always carries `Message-Authenticator`, regardless of the flag.
- If you build an `Access-Request` with `EAP-Message`, `Message-Authenticator` is added automatically — same as before.

If you're talking to a legacy server that can't process the attribute, opt out explicitly:

```python
client = ClientAsync(
    server="localhost",
    secret=b"...",
    dict=Dictionary("dictionary"),
    enforce_ma=False,  # legacy peer; drops BlastRADIUS mitigation
)
```

## Status-Server health checks

[RFC 5997](https://datatracker.ietf.org/doc/html/rfc5997) Status-Server is the canonical "is this RADIUS server alive?" probe. pyrad2 adds the mandatory `Message-Authenticator` automatically.

=== "Async"

    ```python
    from pyrad2.client_async import ClientAsync

    client = ClientAsync(...)
    req = client.create_status_packet()
    reply = await client.send_status_packet(req, port="auth")
    ```

=== "Sync"

    ```python
    from pyrad2.client import Client

    client = Client(...)
    req = client.create_status_packet()
    reply = client.send_status_packet(req, port="auth")
    ```

| `port=` | Expected response |
| --- | --- |
| `"auth"` | `Access-Accept` |
| `"acct"` | `Accounting-Response` |

For a RadSec server, use the dedicated TLS health-check example:

```bash
PYTHONPATH=. uv run examples/status_radsec.py
```

The UDP `examples/status.py` script can't reach a RadSec server - they're on different ports and transports.

## RadSec

!!! info "Status"

    Experimental. Implements [RFC 6614](https://datatracker.ietf.org/doc/html/rfc6614).

RadSec replaces UDP+MD5 with TLS/TCP on port 2083. Auth, accounting, and dynamic authorization all share one mutually-authenticated connection. The default shared secret per the RFC is `radsec`.

For server-side details and a discussion of what the RFC actually changes, see [RadSec in the server docs](server.md#radsec-radius-over-tls).

### Creating a RadSec client

```python
from pyrad2.radsec.client import RadSecClient
from pyrad2.dictionary import Dictionary

client = RadSecClient(
    server="127.0.0.1",
    secret=b"radsec",
    dict=Dictionary("dictionary"),
    certfile="certs/client/client.cert.pem",
    keyfile="certs/client/client.key.pem",
    certfile_server="certs/ca/ca.cert.pem",
)
```

A runnable example is in [`examples/auth_radsec.py`](https://github.com/pyradius/pyrad2/blob/master/examples/auth_radsec.py).

## RADIUS/1.1 (RFC 9765)

!!! warning "Status"

    Experimental. See [the server docs](server.md#radius11-rfc-9765) for a full description of what v1.1 changes.

`RadSecClient` accepts the same `radius_versions=...` kwarg as the server. The default `(V1_0,)` advertises no ALPN string at all - handshakes are byte-identical to historic RadSec. Pass `(V1_0, V1_1)` to offer both; the server picks the highest mutually supported version.

```python
from pyrad2.radsec.client import RadSecClient
from pyrad2.radsec.v11 import RadiusVersion

client = RadSecClient(
    server="127.0.0.1",
    secret=b"radsec",
    dict=Dictionary("dictionary"),
    certfile="certs/client/client.cert.pem",
    keyfile="certs/client/client.key.pem",
    certfile_server="certs/ca/ca.cert.pem",
    radius_versions=(RadiusVersion.V1_0, RadiusVersion.V1_1),
)

req = client.create_auth_packet(User_Name="alice")
req.set_obfuscated("User-Password", "hunter2")
reply = await client.send_packet(req)

print(client._negotiated_version)  # RadiusVersion.V1_1 if both sides agreed
```

### Why `set_obfuscated`?

A client that advertises *both* v1.0 and v1.1 doesn't know which one will be negotiated until the TLS handshake completes. But attribute assignment happens **before** that. `set_obfuscated` defers the encoding decision until send time:

- If v1.0 is negotiated, the password is run through `pw_crypt()`.
- If v1.1 wins, it's sent as plain bytes (TLS provides confidentiality).

The same helper works for `Tunnel-Password`, `MS-MPPE-*-Key`, and other `encrypt=2` attributes - **including vendor-specific ones**, which the deferred path correctly wraps in Vendor-Specific (RADIUS attribute 26).

| Attribute type | Pass | Examples |
| --- | --- | --- |
| `string` | `str` | `User-Password`, `Tunnel-Password` |
| `octets` | `bytes` | `MS-MPPE-Recv-Key`, `MS-MPPE-Send-Key` |

For v1.0-only clients, the historic `req["User-Password"] = req.pw_crypt("...")` pattern still works.

### Strict v1.1 mode and downgrades

If your client is configured for `(V1_1,)` only and the server doesn't advertise the `radius/1.1` ALPN, `send_packet()` returns `None` after raising `PacketError` internally - the client refuses to silently downgrade ([RFC 9765 §3.3](https://datatracker.ietf.org/doc/html/rfc9765#section-3.3)).

To distinguish that case from a normal timeout, check `client.last_error` after a `None` return:

| `last_error` | Meaning |
| --- | --- |
| `PacketError` mentioning *"No common RADIUS protocol"* | Strict-mode refusal |
| `TimeoutError` | Network timeout |
| `None` | Clean no-reply |

### TLS version

`RadSecClient` defaults `minimum_tls_version` to **TLS 1.3** ([RFC 9325](https://datatracker.ietf.org/doc/html/rfc9325) treats 1.2 as legacy; [RFC 9750](https://datatracker.ietf.org/doc/html/rfc9750) mandates 1.3 for RADIUS/1.1).

To bridge a legacy server that can't yet negotiate 1.3, pin the floor at 1.2 explicitly:

```python
import ssl
from pyrad2.radsec.client import RadSecClient

client = RadSecClient(
    server="legacy.example.com",
    secret=b"radsec",
    dict=dictionary,
    minimum_tls_version=ssl.TLSVersion.TLSv1_2,  # legacy peer
)
```

If `radius_versions` includes `V1_1`, the floor is auto-promoted to 1.3 regardless of what you pass (RFC 9750 §3.4).
