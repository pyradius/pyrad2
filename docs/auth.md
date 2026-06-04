# Authentication Methods

pyrad2 ships byte-level primitives plus an `EapMethod` registry so common
authentication flows are a one-line opt-in on the client side. This page
covers everything that lives outside the cleartext-User-Password (PAP)
default: CHAP, EAP-MD5, EAP-GTC, MS-CHAPv2, and EAP-MSCHAPv2.

## At a glance

| Method | Where | Client opt-in | Extra dep |
| --- | --- | --- | --- |
| **PAP** (default) | `User-Password` | nothing — default | none |
| **CHAP** (RFC 1994 / 2865 §2.2) | `pyrad2.chap` | `chap.prepare_chap_request(req, password)` | none |
| **EAP-MD5** (RFC 3748 §5.4) | `pyrad2.eap` | `req.auth_type = "eap-md5"` | none |
| **EAP-GTC** (RFC 3748 §5.6) | `pyrad2.eap` | `req.auth_type = "eap-gtc"` | none |
| **MS-CHAPv2** (RFC 2759 / 2548) | `pyrad2.mschap` | `mschap.prepare_mschap2_request(...)` | `[mschap]` |
| **EAP-MSCHAPv2** (RFC 2759 + EAP framing) | `pyrad2.eap` | `req.auth_type = "eap-mschapv2"` | `[mschap]` |

The EAP methods all flow through one generic client loop. `start()` is
called once before the first send, `respond()` after every
`Access-Challenge` until the server returns `Access-Accept` /
`Access-Reject`. The same code path drives the sync `Client`, async
`ClientAsync`, and `RadSecClient`.

## Optional dependency: `[mschap]`

MS-CHAPv2 and EAP-MSCHAPv2 need exactly two cryptographic primitives:

- **MD4** for the NT Password Hash (RFC 2759 §8.3) — bundled in
  `pyrad2/_md4.py` (textbook RFC 1320 implementation, ~80 lines, no
  external dependency).
- **DES** for the ChallengeResponse primitive (RFC 2759 §8.5) — sourced
  from [`cryptography`](https://cryptography.io). DES is enough subtle
  bit-twiddling that pyrad2 prefers a FIPS-validated implementation
  over bundling its own.

Install via the `[mschap]` extra:

```bash
pip install pyrad2[mschap]
```

If you call any MS-CHAPv2 entry point without the extra installed, you
get a clear `ImportError`:

```
ImportError: MS-CHAPv2 requires the 'cryptography' package for DES.
Install it with: pip install pyrad2[mschap]
```

!!! warning "MS-CHAPv2 is cryptographically broken"

    MS-CHAPv2's response primitive can be reduced to a single DES key
    search (Marlinspike/Ray, DEF CON 2012). pyrad2 ships it strictly
    for interop with legacy RADIUS infrastructure (Windows NPS,
    MikroTik, older PPP VPNs). **Do not use it as a primary
    authentication factor on a new deployment** — wrap it inside
    EAP-PEAP or EAP-TTLS, or pick a modern method.

## CHAP (RFC 1994 / 2865 §2.2)

CHAP is a one-shot transformation applied **before** the
Access-Request goes out — the server doesn't bounce challenges back
mid-exchange, so it doesn't live under `pyrad2.eap`.
`prepare_chap_request` does three things: drops `User-Password`,
computes `MD5(chap_id || password || challenge)`, and stamps
`CHAP-Password` + `CHAP-Challenge` onto the packet.

```python
from pyrad2 import chap
from pyrad2.client_async import ClientAsync

client = ClientAsync(server="...", secret=b"...", dict=dictionary)
await client.initialize_transports(enable_auth=True)

req = client.create_auth_packet(User_Name="alice")
chap.prepare_chap_request(req, password="hunter2")
reply = await client.send_packet(req)
```

`chap_id` and `challenge` default to fresh random values from
`secrets`. Pass them explicitly only for deterministic test vectors.

A runnable end-to-end demo (CHAP client + CHAP-verifying server in one
process) lives at [`scenarios/auth_chap.py`](https://github.com/pyradius/pyrad2/blob/master/scenarios/auth_chap.py)
and runs as `make scenario_auth_chap`.

## EAP-MD5 (RFC 3748 §5.4)

One challenge round. The client computes
`MD5(eap_id || password || challenge)` from the server's challenge and
echoes it back.

```python
req = client.create_auth_packet(
    User_Name="alice",
    User_Password="hunter2",
    auth_type="eap-md5",
)
reply = await client.send_packet(req)
```

The client loop calls `Md5Method.start` (inject EAP-Identity) before
the first send, and `Md5Method.respond` (compute the MD5 digest, copy
the `State` attribute forward) after the `Access-Challenge` reply.

Runnable demo: [`scenarios/auth_eap_md5.py`](https://github.com/pyradius/pyrad2/blob/master/scenarios/auth_eap_md5.py),
`make scenario_auth_eap_md5`.

## EAP-GTC (RFC 3748 §5.6)

Generic Token Card — the server prompts for a credential and the
client returns it in plaintext over `EAP-Message`. Outside a
PEAP/TTLS TLS tunnel this is an eavesdropping target; pyrad2 ships
the leaf so tunnel builders have something to plug in.

```python
req = client.create_auth_packet(
    User_Name="alice",
    User_Password="hunter2",
    auth_type="eap-gtc",
)
reply = await client.send_packet(req)
```

Runnable demo: [`scenarios/auth_eap_gtc.py`](https://github.com/pyradius/pyrad2/blob/master/scenarios/auth_eap_gtc.py),
`make scenario_auth_eap_gtc`.

## MS-CHAPv2 (RFC 2759 / RFC 2548) — non-EAP

When the NAS speaks plain RADIUS MS-CHAPv2 (Microsoft NPS, MikroTik,
older Cisco gear), the client side is one helper call that mutates the
Access-Request in place:

```python
import secrets
from pyrad2 import mschap

# In a real flow the AuthenticatorChallenge arrives from the NAS in a
# prior server message; here it's a stand-in.
auth_challenge = received_from_server  # 16 bytes
peer_challenge = secrets.token_bytes(16)

req = client.create_auth_packet(User_Name="alice")
nt_response = mschap.prepare_mschap2_request(
    req,
    user_name="alice",
    password="hunter2",
    authenticator_challenge=auth_challenge,
    peer_challenge=peer_challenge,
)
reply = await client.send_packet(req)

# Optional: verify the server's mutual-auth proof if it returned
# MS-CHAP2-Success.
if "MS-CHAP2-Success" in reply:
    if not mschap.verify_authenticator_response(
        "hunter2",
        nt_response,
        peer_challenge,
        auth_challenge,
        "alice",
        reply["MS-CHAP2-Success"][0],
    ):
        raise RuntimeError("Server failed MS-CHAPv2 mutual authentication")
```

The lower-level primitives — `nt_password_hash`, `challenge_hash`,
`challenge_response`, `generate_nt_response`, `build_mschap2_response`,
`generate_authenticator_response` — are exported from `pyrad2.mschap`
for callers who need to build packets by hand. They're pinned by the
[RFC 2759 §D test vector](https://datatracker.ietf.org/doc/html/rfc2759#appendix-D)
in the test suite.

## EAP-MSCHAPv2 (RFC 2759 + EAP framing)

MS-CHAPv2 wrapped in EAP. Two challenge rounds (Challenge → Response →
Success-Request → Success-Response → Access-Accept) — the
`MschapV2Method` is **stateful per conversation** and carries the
authenticator challenge, peer challenge, and NT-Response across rounds
so it can verify the server's Authenticator Response on the
Success-Request.

```python
req = client.create_auth_packet(
    User_Name="alice",
    User_Password="hunter2",
    auth_type="eap-mschapv2",
)
reply = await client.send_packet(req)
```

The client loop creates a fresh `MschapV2Method` instance per call so
concurrent EAP-MSCHAPv2 clients don't share state.

Runnable demo: [`scenarios/auth_eap_mschapv2.py`](https://github.com/pyradius/pyrad2/blob/master/scenarios/auth_eap_mschapv2.py),
`make scenario_auth_eap_mschapv2`.

## Adding a new EAP method

The `EapMethod` ABC has two hooks. To add `eap-foo`:

```python
from pyrad2.eap import EapMethod, register_method


class FooMethod(EapMethod):
    def start(self, pkt):
        """Mutate ``pkt`` in place to seed the first send."""
        ...

    def respond(self, pkt, challenge):
        """Mutate ``pkt`` in place to answer an Access-Challenge.

        Copy the ``State`` attribute forward (RFC 2865 §5.24).
        """
        ...


register_method("eap-foo", FooMethod)
```

Callers then set `req.auth_type = "eap-foo"` and the client driver
handles everything else — id allocation, authenticator regeneration
(async only), Message-Authenticator, challenge loop termination.
Stateful methods register their class as the factory (one fresh
instance per conversation); stateless ones can register an instance.

## Security defaults

- `Message-Authenticator` is enforced on every `Access-Request` and
  every `Access-*` reply by default (BlastRADIUS / CVE-2024-3596
  mitigation). See [Message-Authenticator](client.md#message-authenticator).
- `PYRAD2_TRACE=1` plus `PYRAD2_TRACE_UNSAFE=1` dumps wire bytes
  including obfuscated `User-Password` values — never enable in
  production unless the log destination is access-controlled at the
  same level as the shared secret.
- EAP-MD5 and EAP-GTC do not provide confidentiality. Use them only
  inside a TLS tunnel or on a trusted segment.
- MS-CHAPv2 is cryptographically broken — see the warning above.
