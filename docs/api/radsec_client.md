# RadSec Client

RadSec is a TCP/TLS stream transport. `RadSecClient` reuses its TLS connection
by default so multiple `send_packet()` calls can share the same connection. This
is the recommended mode for normal RadSec use.

## TLS defaults

`RadSecClient` ships with secure TLS defaults:

- the server certificate is validated against `certfile_server`
- hostname validation is on (`check_hostname=True`)
- **TLS 1.3 or newer** is required by default ([RFC 9325](https://datatracker.ietf.org/doc/html/rfc9325) deprecates TLS 1.1 and below and treats 1.2 as legacy; [RFC 9750](https://datatracker.ietf.org/doc/html/rfc9750) mandates 1.3 for RADIUS/1.1)
- the client can optionally pin server certificates by SHA-256 fingerprint via `allowed_server_fingerprints`

To bridge a legacy server that can't yet negotiate 1.3 on a pure v1.0 deployment, pin the floor at 1.2 explicitly:

```python
import ssl

client = RadSecClient(
    server="legacy.example.com",
    secret=b"radsec",
    dict=dictionary,
    minimum_tls_version=ssl.TLSVersion.TLSv1_2,  # legacy peer
)
```

If `radius_versions` includes `V1_1`, the floor is auto-promoted to 1.3 regardless of what you pass.

Use `reuse_connection=False` only as a legacy/compatibility escape hatch when a
deployment specifically needs one TLS connection per packet, such as for
interoperability debugging, short-lived scripts, or a peer that cannot handle
multiple RADIUS packets on one TLS stream:

```python
client = RadSecClient(
    server="127.0.0.1",
    secret=b"radsec",
    dict=dictionary,
    certfile="certs/client/client.cert.pem",
    keyfile="certs/client/client.key.pem",
    certfile_server="certs/ca/ca.cert.pem",
    reuse_connection=False,
)
```

The existing `timeout` value is used for connection establishment, writing, and
waiting for each response packet. If a reusable connection fails, the client
closes it, waits `reconnect_backoff` seconds, and retries up to `retries` times:

```python
client = RadSecClient(
    server="127.0.0.1",
    secret=b"radsec",
    dict=dictionary,
    certfile="certs/client/client.cert.pem",
    keyfile="certs/client/client.key.pem",
    certfile_server="certs/ca/ca.cert.pem",
    retries=3,
    timeout=5,
    reconnect_backoff=0.25,
)
```

When you are done with a reusable client, close it explicitly or use it as an
async context manager:

```python
async with RadSecClient(...) as client:
    reply = await client.send_packet(request)
```

`RadSecClient` automatically adds `Message-Authenticator` to outgoing
`Access-Request` packets that contain `EAP-Message`.

Use `create_status_packet()` for RFC 5997 Status-Server health checks. The
request automatically includes the mandatory `Message-Authenticator`:

```python
request = client.create_status_packet()
reply = await client.send_packet(request)
```

The UDP Status-Server example (`examples/status.py`) talks to a normal RADIUS
server on UDP/1812. To check a RadSec server such as
`examples/server_radsec.py`, use the TLS/TCP example instead:

```shell
make status_radsec
```

::: pyrad2.radsec.client
    handler: python
