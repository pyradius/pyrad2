# pyrad2

<img src="logo.png" width="10%" height="auto">

[![Tests](https://github.com/pyradius/pyrad2/actions/workflows/python-test.yml/badge.svg)](https://github.com/pyradius/pyrad2/actions/workflows/python-test.yml)
[![python](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/uv)
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)

**A modern Python toolkit for building RADIUS clients and servers.**

[pyrad2](https://github.com/pyradius/pyrad2) gives you the protocol - packet encoding, dictionary parsing, transport handling, retransmission, TLS - so you can write the business logic. Build an authentication backend, a CoA proxy, a RadSec accounting collector, or a network-access controller without touching wire formats.

```python
from pyrad2.client_async import ClientAsync
from pyrad2.dictionary import Dictionary

client = ClientAsync(server="radius.example.com", secret=b"...", dict=Dictionary("dictionary"))

req = client.create_auth_packet(User_Name="alice", User_Password="hunter2")
reply = await client.send_packet(req)

if reply.code == PacketType.AccessAccept:
    print("Welcome,", reply["User-Name"][0])
```

## Where to next

<div class="grid cards" markdown>

-   **New here?** &nbsp;→ [Getting Started](setup.md)

    Install, run a working exchange in 30 seconds, and learn the three concepts you actually need.

-   **Building a server?** &nbsp;→ [Running a RADIUS Server](server.md)

    Authentication, accounting, CoA, Status-Server, duplicate detection, RadSec.

-   **Building a client?** &nbsp;→ [Making RADIUS Requests](client.md)

    Send your first request, then layer in EAP, Message-Authenticator, health checks, and RadSec.

-   **Coming from `pyrad`?** &nbsp;→ [Compatibility](compatibility.md)

    What changed in the fork and what you need to update.

</div>

## What's in the box

| Feature | Spec |
| --- | --- |
| RADIUS client & server (sync + async) | [RFC 2865](https://datatracker.ietf.org/doc/html/rfc2865) |
| RadSec - RADIUS over TLS | [RFC 6614](https://datatracker.ietf.org/doc/html/rfc6614) |
| RADIUS/1.1 over RadSec (experimental) | [RFC 9765](https://datatracker.ietf.org/doc/html/rfc9765) |
| CoA & Disconnect (Dynamic Authorization) | [RFC 5176](https://datatracker.ietf.org/doc/html/rfc5176) |
| Status-Server health checks | [RFC 5997](https://datatracker.ietf.org/doc/html/rfc5997) |
| Duplicate detection / response cache | [RFC 5080 §2.2.2](https://datatracker.ietf.org/doc/html/rfc5080#section-2.2.2) |
| BlastRADIUS-safe defaults | [CVE-2024-3596](https://www.blastradius.fail/) - `Message-Authenticator` enforced on `Access-Request` out of the box |
| FreeRADIUS dictionary support | Extended attributes, vendor formats, EVS, nested TLVs, WiMAX continuation, RFC 8044 arrays - see [Dictionary Reference](dictionary.md) |
| FreeRADIUS interop conformance | 281 dictionaries + 41 packet vectors regression-tested against upstream FreeRADIUS - see [FreeRADIUS Conformance](conformance.md) |
| Authentication methods | PAP, CHAP, EAP-MD5, EAP-GTC out of the box; MS-CHAPv2 + EAP-MSCHAPv2 via `pip install pyrad2[mschap]` - see [Authentication Methods](auth.md) |
| Wire-level packet tracing | `PYRAD2_TRACE=1` + `PYRAD2_TRACE_UNSAFE=1` |

pyrad2 is a **library**, not a daemon. It is not a drop-in replacement for [FreeRADIUS](https://freeradius.org); it gives you the moving parts to build your own.

## Project

- **Source**: [github.com/pyradius/pyrad2](https://github.com/pyradius/pyrad2)
- **Releases**: [Release notes](https://github.com/pyradius/pyrad2/releases)
- **Issues & PRs**: [Issue tracker](https://github.com/pyradius/pyrad2/issues) - PRs are very welcome.
