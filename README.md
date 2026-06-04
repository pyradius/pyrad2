<img src="docs/logo.png" width="10%" height="auto">

# pyrad2

[![Tests](https://github.com/pyradius/pyrad2/actions/workflows/python-test.yml/badge.svg)](https://github.com/pyradius/pyrad2/actions/workflows/python-test.yml)
[![python](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/uv)
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)

**A modern Python toolkit for building RADIUS clients and servers.**

pyrad2 gives you the protocol - packet encoding, dictionary parsing, transport handling, retransmission, TLS - so you can write the business logic. Build an authentication backend, a CoA proxy, a RadSec accounting collector, or a network-access controller without touching wire formats.

> 📚 **Full documentation: [pyradius.github.io/pyrad2](https://pyradius.github.io/pyrad2/)**

## Install

```bash
pip install pyrad2     # or: uv add pyrad2
```

Requires Python **3.12+**.

## Quick look

```python
from pyrad2.client_async import ClientAsync
from pyrad2.dictionary import Dictionary
from pyrad2.constants import PacketType

client = ClientAsync(server="radius.example.com", secret=b"...", dict=Dictionary("dictionary"))
await client.initialize_transports(enable_auth=True)

req = client.create_auth_packet(User_Name="alice", User_Password="hunter2")
reply = await client.send_packet(req)

if reply.code == PacketType.AccessAccept:
    print("Welcome,", reply["User-Name"][0])
```

Head to the [Getting Started guide](https://pyradius.github.io/pyrad2/setup/) for the full walkthrough.

## What's in the box

| Feature | Spec |
| --- | --- |
| RADIUS client & server (sync + async) | [RFC 2865](https://datatracker.ietf.org/doc/html/rfc2865) |
| RadSec - RADIUS over TLS | [RFC 6614](https://datatracker.ietf.org/doc/html/rfc6614) |
| RADIUS/1.1 over RadSec (experimental) | [RFC 9765](https://datatracker.ietf.org/doc/html/rfc9765) |
| CoA & Disconnect (Dynamic Authorization) | [RFC 5176](https://datatracker.ietf.org/doc/html/rfc5176) |
| Status-Server health checks | [RFC 5997](https://datatracker.ietf.org/doc/html/rfc5997) |
| Duplicate detection / response cache | [RFC 5080 §2.2.2](https://datatracker.ietf.org/doc/html/rfc5080#section-2.2.2) |
| FreeRADIUS dictionary support | Extended attributes, vendor formats, EVS |
| Wire-level packet tracing | `PYRAD2_TRACE=1` |

pyrad2 is a **library**, not a daemon. It is not a drop-in replacement for [FreeRADIUS](https://freeradius.org); it gives you the moving parts to build your own.

## See it run

Two complementary surfaces ship with the repo:

- **[`scenarios/`](scenarios)** - single-process, end-to-end demos. A server **and** a client run in the same event loop so the full exchange shows up on one log. **Don't edit them - they're runnable explanations.**
- **[`examples/`](examples)** - operational scripts you copy into your project and edit.

```bash
make demo                  # all scenarios sequentially

make scenario_auth         # Access-Request → Access-Accept (UDP)
make scenario_acct         # Accounting-Request → Accounting-Response
make scenario_coa          # CoA-Request → CoA-ACK (RFC 5176)
make scenario_status       # Status-Server health check (RFC 5997)
make scenario_dedup        # Duplicate detection (RFC 5080)
make scenario_radsec       # RadSec over mutual TLS (RFC 6614)
make scenario_radsec_v11   # RADIUS/1.1 over RadSec (RFC 9765)
make scenario_proxy        # Client → Proxy → Upstream RADIUS server (RFC 2865 §2)
```

Watch the actual bytes on the wire by setting `PYRAD2_TRACE=1` on any script:

```bash
PYRAD2_TRACE=1 make scenario_auth
```

## Documentation

- **[Getting Started](https://pyradius.github.io/pyrad2/setup/)** - install, RADIUS in one minute, run an exchange
- **[Running a Server](https://pyradius.github.io/pyrad2/server/)** - auth, accounting, CoA, RadSec, RADIUS/1.1
- **[Making Requests](https://pyradius.github.io/pyrad2/client/)** - clients, EAP, health checks, RadSec
- **[Dictionary Reference](https://pyradius.github.io/pyrad2/dictionary/)** - every supported type and option
- **[Migrating from pyrad](https://pyradius.github.io/pyrad2/compatibility/)** - breaking changes since 2.0

## Tests

```bash
make test
```

## Author, Copyright, Availability

pyrad2 is currently maintained by Nicholas Amorim.

pyrad was written by [Wichert Akkerman](wichert@wiggy.net) and is maintained by Christian Giese (GIC-de) and Istvan Ruzman (Istvan91).

This project is licensed under a BSD license. Copyright and license information can be found in [LICENSE.txt](https://github.com/pyradius/pyrad2/blob/master/LICENSE.txt).

Bugs and wishes can be submitted in the pyrad2 [issue tracker](https://github.com/pyradius/pyrad2/issues) on GitHub. PRs are very welcome.
