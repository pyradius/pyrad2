# FreeRADIUS Conformance

pyrad2 ships a dedicated conformance suite that loads the upstream FreeRADIUS dictionary corpus and decodes its packet test vectors. The goal is plain: **if a dictionary works in FreeRADIUS, it should work in pyrad2 too** — without modification, without per-vendor patching, without surprises.

This page covers what the suite tests, what currently passes, what doesn't, and how to run it.

## Goal

pyrad2 is a library, not a daemon — but the dictionaries it parses, the wire bytes it decodes, and the VSAs it round-trips are the same ones FreeRADIUS deployments produce. The conformance suite is the test that proves that's actually true.

Three things matter:

- **Dictionary fidelity.** Every `dictionary.<vendor>` file in FreeRADIUS's `share/` should load without an error. There are 244 of them, covering Cisco, Aruba, Juniper, 3GPP, Aerohive, and so on — anything pyrad2 rejects is something a real deployment can't talk to.
- **Wire compatibility.** RADIUS packets captured against FreeRADIUS deployments should decode to the same attribute names and types pyrad2 would produce on the other side.
- **No silent degradation.** When pyrad2 *doesn't* understand a construct — and there are still a handful — that gap is a documented `xfail`, not a stack trace.

## What the suite tests

Two parametrized test files under [`tests/conformance/`](https://github.com/pyradius/pyrad2/tree/master/tests/conformance):

| File | What it asserts |
| --- | --- |
| `test_freeradius_dictionaries.py` | Each of the 244 vendor dictionaries loads on top of a real FreeRADIUS RFC base |
| `test_freeradius_packet_vectors.py` | Each `decode-proto` test vector from FreeRADIUS v4's protocol unit tests decodes cleanly through `parse_packet` |

The corpus is pinned to specific FreeRADIUS revisions — `release_3_2_5` for the flat dictionary layout, `master` at a fixed SHA for the packet vectors — and fetched on demand by [`scripts/fetch_freeradius_corpus.py`](https://github.com/pyradius/pyrad2/blob/master/scripts/fetch_freeradius_corpus.py). The fetched tree lives under `tests/conformance/_corpus/` (gitignored). If it's not present, every conformance test cleanly skips.

## Running it

```bash
make conformance-fetch    # one-time per pin: sparse-clones FreeRADIUS
make conformance-test     # runs the suite against the fetched corpus
```

In CI, the [`conformance` job](https://github.com/pyradius/pyrad2/blob/master/.github/workflows/python-test.yml) runs both targets on every push and PR. The default `make test` excludes `tests/conformance/` so contributor flow stays fast and network-free.

## Stacking model

The dictionary test mirrors what a real pyrad2 user does: load the RFC base, then layer vendor dictionaries on top. The session fixture walks the `$INCLUDE` lines in FreeRADIUS's root `share/dictionary` and cumulatively loads every RFC file that parses, then layers `dictionary.freeradius` and `dictionary.freeradius.internal` and `dictionary.dhcp` so vendor files that depend on FR-internal attribute declarations can find them. Each vendor file is then loaded one more time on top of that full stack.

That's the configuration the per-vendor parametrized test reports against. A file passes if pyrad2 can parse it stacked on the FreeRADIUS base; it `xfail`s if a documented limitation gets in the way.

## What works today

As of the latest commit, **281 dictionaries and all 41 packet vectors pass**. The full breakdown:

- **All RFC dictionaries** in the FreeRADIUS root `$INCLUDE` chain — including the RFC 6929 / 7499 / 7930 / 8045 / 8559 extended-attribute files that use 3-level dotted codes.
- **All major vendor families** — Cisco, Aruba, Juniper, Microsoft, Aerohive, 3GPP, Alcatel-Lucent, HP, ZyXEL, and so on.
- **WiMAX and Telrad** — the dictionaries declared with `format=1,1,c` (RFC 5904 long-packed VSAs).
- **DHCP-in-RADIUS** — `dictionary.dhcp` and friends, using the `array` flag.
- **FreeRADIUS-internal dictionaries** — `dictionary.freeradius`, `dictionary.freeradius.internal`, `dictionary.compat`.

On the wire side, every `decode-proto` test vector from FreeRADIUS v4's protocol unit tests (in `src/tests/unit/protocols/radius/*.txt`) — covering Access-Request, Access-Accept, Access-Challenge, Accounting-Request, CoA, EAP, RFC 3162 / 4675 / 5176 / 6929 extended attributes, vendor TLVs, and the EAPoL examples — decodes without raising. The decoder also accepts the `Vendor-Specific = { raw.1 = { raw.6 = ... } }` nested-TLV shape FreeRADIUS uses for deep RFC 6929 extended attributes.

The fuzzer-derived `foreign.txt` and `errors.txt` vectors are deliberately skipped: they're crafted to test the *rejection* path, not real-world compatibility.

## What FreeRADIUS dictionary features pyrad2 implements

The conformance work drove implementation of every FreeRADIUS dictionary extension that real-world deployments actually use:

| Feature | Where | What it does |
| --- | --- | --- |
| `vsa` data type | parser | Alias for the bare Vendor-Specific attribute (RFC 2865 code 26) |
| `ipv4prefix` data type | parser | RFC 5090 — 1 reserved + 1 prefix-len + 4-byte address octets |
| `combo-ip` data type | parser + codec | "Either IPv4 or IPv6, decided by wire length" — 4 or 16 bytes |
| 3+ level nested TLV codes | parser + codec | Full wire encode/decode for codes like `241.5.1` |
| `uint8` / `uint16` / `uint32` / `uint64` / `int32` aliases | parser | Normalised to `byte` / `short` / `integer` / `integer64` / `signed` |
| `virtual` attribute flag | parser + encoder | Marks server-internal attributes; encoder skips them on the wire |
| `array` attribute flag (RFC 8044 §3.8) | parser + codec | Multiple fixed-length values packed into one AVP; decoder splits back out |
| `secret` attribute flag | parser | Accepted as a no-op for parity with FR-internal dicts |
| `format=...,c` continuation | parser + codec | RFC 5904 / WiMAX long-packed VSAs with the 0x80 More-flag continuation byte |

Each of these has unit tests in [`tests/test_packet.py`](https://github.com/pyradius/pyrad2/tree/master/tests/test_packet.py) covering the round-trip — encode, decode, and equivalence — so the conformance gains aren't paper wins.

## Corner cases that don't load

Four dictionaries still `xfail`. Each is documented with a structured reason in [`tests/conformance/test_freeradius_dictionaries.py`](https://github.com/pyradius/pyrad2/blob/master/tests/conformance/test_freeradius_dictionaries.py), and the `xfail` is `strict=True` — the moment pyrad2 grows support for one of them, the test "unexpectedly passes" and forces removal from the list.

| Dictionary | Reason | Notes |
| --- | --- | --- |
| `dictionary.aruba` | `fr-dict-forward-ref` | Declares `VALUE` entries for `Aruba-PoE-Allocate-By-Method`, which is never defined as an `ATTRIBUTE` anywhere in the FreeRADIUS corpus. This is a bug in the upstream dictionary, not in pyrad2 |
| `dictionary.freedhcp` | `fr-dict-forward-ref` | Same shape as `aruba` — `VALUE` for `FreeDHCP-Opcode`, which has no `ATTRIBUTE` declaration |
| `dictionary.juniper` | `fr-quirk-typo` | Two lines use a capitalised `String` instead of `string`. pyrad2 is strict about case |
| `dictionary.freeradius.evs5` | `fr-evs-format-syntax` | Uses `BEGIN-VENDOR FreeRADIUS format=Extended-Vendor-Specific-5` — an alternative syntax for binding EVS to an Extended wrapper. pyrad2 currently only understands the `parent=NAME` form |

The first three aren't pyrad2's problem to solve. The last one is, and is a candidate for a future PR — the work is straightforward but mechanical: thread the named-wrapper resolution through `__parse_begin_vendor`.

## Adding to the suite

The conformance suite is designed to be self-maintaining. When you add a new dictionary feature:

1. Land the parser + codec change with unit tests under `tests/test_packet.py` or `tests/test_dictionary.py`.
2. Drop the relevant entries from `_INCOMPATIBLE_ON_RFC_BASE`.
3. Bump `_MIN_LOADABLE_DICTIONARIES` to reflect the new floor.

The `xfail(strict=True)` markers do the rest of the bookkeeping: a previously-failing dict that starts passing trips the suite until the entry is removed, and a previously-passing dict that starts failing trips it the other way.

When FreeRADIUS releases a new pin worth tracking, edit the `ref` value in [`scripts/fetch_freeradius_corpus.py`](https://github.com/pyradius/pyrad2/blob/master/scripts/fetch_freeradius_corpus.py) and re-run `make conformance-fetch`. Any new dictionaries that don't parse will fail loudly, which is the point.
