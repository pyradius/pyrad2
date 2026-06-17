# Getting Started

This page takes you from zero to a working RADIUS exchange in about 30 seconds - then explains what you just saw.

## 1. Install

=== "pip"

    ```bash
    pip install pyrad2
    ```

=== "uv"

    ```bash
    uv add pyrad2
    ```

pyrad2 requires Python **3.12 or newer**.

### Optional: MS-CHAPv2 support

MS-CHAPv2 and EAP-MSCHAPv2 (RFC 2759) need a DES primitive that modern
Python stacks no longer expose. If you plan to use either method,
install with the `[mschap]` extra:

=== "pip"

    ```bash
    pip install "pyrad2[mschap]"
    ```

=== "uv"

    ```bash
    uv add "pyrad2[mschap]"
    ```

This pulls in the [`cryptography`](https://cryptography.io) package
(~3 MB on install). MD4 (the other primitive MS-CHAPv2 needs) is
bundled inside pyrad2 — no separate dependency. Every other
authentication method pyrad2 ships (PAP, CHAP, EAP-MD5, EAP-GTC) works
with the base install.

See [Authentication Methods](auth.md) for the full method matrix and
client snippets.

### Async runtime: asyncio and uvloop

`ServerAsync` and `ClientAsync` work on any event loop that implements
the asyncio transport protocols. In practice that means both **vanilla
asyncio** and **[uvloop](https://github.com/MagicStack/uvloop)** are supported.
Embedding pyrad2 inside a [FastAPI](https://fastapi.tiangolo.com/) /
[Uvicorn](https://www.uvicorn.org/) host (which defaults to uvloop on
Linux/macOS) needs no special setup.

## 2. RADIUS in one minute

If you've never worked with RADIUS, here's what you need to know before reading another line.

- **RADIUS is a request/response protocol** for *"is this user/device allowed?"* and *"what just happened on the network?"* questions. It's how a Wi-Fi access point asks a central server whether to let someone on.
- **There are two parties.** The **client** (often a router, switch, VPN concentrator, or "NAS" - Network Access Server) asks the question. The **server** answers.
- **There are three flavors of conversation:**
    - **Authentication** - `Access-Request` -> `Access-Accept` / `Access-Reject` / `Access-Challenge`
    - **Accounting** - `Accounting-Request` -> `Accounting-Response` (the client tells the server "user X started/stopped using N bytes")
    - **Dynamic authorization** - `CoA-Request` / `Disconnect-Request` from a *Dynamic Authorization Server* to a NAS, to change or terminate an active session
- **Packets carry attributes**, not free-form payloads. `User-Name`, `NAS-IP-Address`, `Framed-IP-Address` - every value has a numeric code and a type.
- **A shared secret** between client and server is used to authenticate packets and obfuscate passwords. Both sides must agree on it.
- **A dictionary** (a plain text file) tells pyrad2 which attribute name maps to which code and type. Both client and server must load compatible dictionaries.

That's it. The rest is detail.

## 3. See a real exchange

The fastest way to understand pyrad2 is to watch a complete exchange in one terminal. The repo ships **scenarios** - single-process scripts that run a server *and* a client in one event loop and exit.

```bash
make scenario_auth     # Access-Request -> Access-Accept (RFC 2865)
make scenario_acct     # Accounting-Request -> Accounting-Response
make scenario_coa      # CoA-Request -> CoA-ACK (RFC 5176)
make scenario_status   # Status-Server health check (RFC 5997)
make scenario_dedup    # Duplicate detection (RFC 5080)
make scenario_radsec   # RadSec over mutual TLS (RFC 6614)
make demo              # all of the above, in sequence
```

To **watch the actual bytes** on the wire, set `PYRAD2_TRACE=1` **and** `PYRAD2_TRACE_UNSAFE=1`:

```bash
PYRAD2_TRACE=1 PYRAD2_TRACE_UNSAFE=1 make scenario_auth
```

Every packet is dumped with direction (`→` outgoing, `←` incoming), code, id, length, authenticator, decoded attributes, and a hex view of the raw bytes:

```
[pyrad2 trace] → AccessRequest id=5 len=39
    authenticator: de0f04abde127b093c5e456b9f51ed81
    attributes:
      User-Name: ['alice']
      NAS-IP-Address: ['192.168.1.10']
      Service-Type: ['Login-User']
    raw:
        0000  01 05 00 27 de 0f 04 ab de 12 7b 09 3c 5e 45 6b  ...'......{.<^Ek
        0010  9f 51 ed 81 01 07 61 6c 69 63 65 04 06 c0 a8 01  .Q....alice.....
        0020  0a 06 06 00 00 00 01                             .......
```

!!! danger "Why two env vars?"

    The trace dumps the Request Authenticator and the **obfuscated** `User-Password` verbatim. Anyone who later reads the log archive *and* knows the shared secret (commonly stored in the same config the operator reading the log can see) can recover the plaintext password — the RFC 2865 obfuscation is fully reversible with both inputs. `PYRAD2_TRACE_UNSAFE=1` is an acknowledgement that the destination of these log lines is access-controlled at the same level as the shared secret. Setting `PYRAD2_TRACE=1` without it logs a warning and keeps the trace **disabled**.

`PYRAD2_TRACE` works on any script - scenarios, examples, or your own code - and costs nothing when off.

!!! tip "Scenarios vs examples"

    Scenarios are **runnable explanations** - don't edit them. When you're ready to write your own integration, copy from [`examples/`](https://github.com/pyradius/pyrad2/tree/master/examples) instead: those are operational scripts (one terminal per process) designed to be cribbed.

## 4. Load a dictionary

Before you can build packets, pyrad2 needs a dictionary to know what `User-Name` *means*. Dictionaries are plain text files with one definition per line:

```
ATTRIBUTE User-Name      1  string
ATTRIBUTE User-Password  2  string
ATTRIBUTE CHAP-Password  3  octets
```

Two reference dictionaries are included in the repo:

- [`examples/dictionary`](https://github.com/pyradius/pyrad2/blob/master/examples/dictionary) - a working starter dictionary
- [`examples/dictionary.freeradius`](https://github.com/pyradius/pyrad2/blob/master/examples/dictionary.freeradius) - FreeRADIUS vendor-specific attributes

Drop one (or both) into your project, then load it:

```python
from pyrad2.dictionary import Dictionary

d = Dictionary("dictionary")  # path to a file, or any file-like object
```

!!! warning "Same dictionary on both sides"

    Your client and server must load **compatible dictionaries** - that's how they agree on what attribute code `1` means. Mismatched dictionaries are the most common source of "why is my packet empty?" confusion.

pyrad2 reads real-world FreeRADIUS dictionaries with broad fidelity, including extended attributes, vendor-specific formats, and TLV. See the [Dictionary Reference](dictionary.md) for the full feature matrix.

## 5. Where to next

You now have everything you need to read the rest of the docs.

<div class="grid cards" markdown>

-   **[Run a server →](server.md)**

    Subclass `ServerAsync`, handle Access-Requests, send replies, enable RadSec.

-   **[Send requests →](client.md)**

    Build packets, send them, handle replies, do EAP, do RadSec.

-   **[Dictionary reference →](dictionary.md)**

    Every supported data type, attribute option, and RFC 6929 extension.

-   **[API reference →](api/server.md)**

    Per-module documentation generated from source.

</div>
