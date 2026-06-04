# scenarios

Single-process, end-to-end demos. Each script runs an async pyrad2
server **and** an async pyrad2 client in the same event loop, performs
one exchange, and exits. The point is to **see both sides of a RADIUS
flow on one log** without having to spin up two terminals.

This is intentionally different from [`examples/`](../examples), which
is operational code you can crib into your own project. Scenarios are
not meant to be edited — they are runnable explanations.

## Running

```bash
python scenarios/auth.py
python scenarios/acct.py
python scenarios/coa.py
python scenarios/status.py
python scenarios/dedup.py
python scenarios/radsec_auth.py
python scenarios/radsec_v11.py
```

Or via the Makefile:

```bash
make scenario_auth         # Access-Request → Access-Accept (UDP, RFC 2865)
make scenario_acct         # Accounting-Request → Accounting-Response
make scenario_coa          # CoA-Request → CoA-ACK (RFC 5176)
make scenario_status       # Status-Server health check (RFC 5997)
make scenario_dedup        # Duplicate detection / response cache (RFC 5080)
make scenario_radsec       # RadSec (RFC 6614) — mutual TLS, Access-Request
make scenario_radsec_v11   # RADIUS/1.1 (RFC 9765) — ALPN-negotiated v1.1 over RadSec
make scenario_proxy        # Client → Proxy → Upstream — RADIUS proxy data flow
make scenario_auth_chap            # CHAP authentication (RFC 1994 / 2865 §2.2)
make scenario_auth_eap_md5         # EAP-MD5 challenge/response (RFC 3748 §5.4)
make scenario_auth_eap_gtc         # EAP-GTC prompt-and-response (RFC 3748 §5.6)
make scenario_auth_eap_mschapv2    # EAP-MSCHAPv2 — needs pip install pyrad2[mschap]
make demo                  # all of the above sequentially
```

The RadSec scenario uses the test certificates in `examples/certs/`,
which are signed for `localhost`/`127.0.0.1`. Do not reuse them in
production.

## Wire-level visibility

Set `PYRAD2_TRACE=1` (or `true`, `yes`, `on`) on any scenario — or any
script that calls into pyrad2 — to dump every packet that flows through
`request_packet` / `reply_packet` / `decode_packet`. Each dump shows the
direction, packet code, id, length, authenticator, decoded AVPs, and a
hex view of the raw bytes:

```bash
PYRAD2_TRACE=1 python scenarios/auth.py
```

Trace is gated by an environment variable, costs nothing when off, and
goes through the same `loguru` pipeline as the rest of pyrad2's
logging — configure or suppress it the same way you configure your own
log handlers.
