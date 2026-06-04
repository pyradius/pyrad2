Changelog
=========

3.1 - Unreleased
----------------

This release is about **real-world FreeRADIUS interop**. pyrad2 now ships
a conformance suite that loads the upstream FreeRADIUS dictionary corpus
and decodes its packet test vectors on every CI run, and every gap the
suite surfaced got a real codec. As of this entry, 281 dictionaries (RFC
base, FreeRADIUS-internal, and vendor) plus all 41 of the v4 packet test
vectors pass; only four dictionaries still ``xfail``, and three of those
are upstream FreeRADIUS dictionary bugs.

# FreeRADIUS conformance suite (NEW)

- **New conformance test surface** under
  ``tests/conformance/``. ``test_freeradius_dictionaries.py`` loads every
  ``share/dictionary.<vendor>`` file from FreeRADIUS ``release_3_2_5``
  on top of a real RFC base; ``test_freeradius_packet_vectors.py``
  decodes every ``decode-proto`` test vector from FreeRADIUS v4's
  ``src/tests/unit/protocols/radius/*.txt`` through ``parse_packet``.
  The corpus is fetched on demand (gitignored) so the default
  ``make test`` stays fast and network-free.
- **New ``scripts/fetch_freeradius_corpus.py``** sparse-clones two pinned
  FreeRADIUS slices into ``tests/conformance/_corpus/`` and records the
  resolved SHA in a MANIFEST so months-later debugging always knows
  which upstream revision the fixtures came from.
- **New ``make conformance-fetch`` / ``make conformance-test`` targets**
  and a dedicated ``conformance`` job in ``python-test.yml`` that runs
  alongside the existing lint / typecheck / test matrix.
- **Stacked-load model**: the per-vendor parametrized test loads every
  vendor file on top of a session-built base — the cumulative set of
  RFC dictionaries that parse cleanly, plus ``dictionary.freeradius``,
  ``dictionary.freeradius.internal``, and ``dictionary.dhcp``. This
  mirrors what real deployments do and turns "needs parent context"
  failures into actual signal.
- **Known-incompatible inventory** with structured reasons and
  ``xfail(strict=True)``: the moment pyrad2 grows support for a listed
  dict, the test fails and forces removal from the list. Documented
  per-reason in ``test_freeradius_dictionaries.py``; only four entries
  remain.
- **New ``docs/conformance.md``** documenting the suite, what passes,
  the four remaining xfails and which are upstream bugs vs. pyrad2's
  to fix.

# Dictionary parser

- **N-level dotted codes** (e.g. ``241.5.1``). The parser previously
  rejected codes deeper than two levels with "nested tlvs are not
  supported." Sub-attribute keys are now tuples of every code from the
  root container down; the per-file ``tlvs`` lookup is seeded from
  previously-parsed attributes so a sub-attribute in one dictionary can
  reference a container declared in another (e.g. ``dictionary.rfc7499``
  declaring ``241.X`` under ``Extended-Attribute-1`` from
  ``dictionary.rfc6929``). Undefined-parent failures now raise a clean
  ``ParseError`` with the chain spelled out instead of a bare
  ``KeyError``.
- **New data types**
  - ``vsa`` — parser token for the bare ``Vendor-Specific`` attribute
    (RFC 2865 code 26), functionally equivalent to ``octets``. Lets
    ``dictionary.rfc2865`` load.
  - ``ipv4prefix`` (RFC 5090), IPv4 mirror of ``ipv6prefix`` (1 reserved
    + 1 prefix-length + 4-byte address). Accepted at the parser layer;
    wire codec deliberately deferred.
  - ``combo-ip`` — full codec. Encoder dispatches on input shape via
    ``ip_address()``; decoder dispatches on wire length (4 → IPv4, 16
    → IPv6, anything else rejected). Wired into both
    ``encode_attr`` / ``decode_attr`` and the parser's allowlist.
- **FreeRADIUS v4 type aliases.** ``uint8`` / ``uint16`` / ``uint32`` /
  ``uint64`` / ``int32`` are normalised at parse time to the canonical
  ``byte`` / ``short`` / ``integer`` / ``integer64`` / ``signed``
  tokens. Single point of truth; no downstream changes needed.
- **New attribute flags**
  - ``virtual`` — marks server-internal attributes; the encoder skips
    them entirely. Lets ``dictionary.freeradius.internal`` load.
  - ``array`` (RFC 8044 §3.8), multiple fixed-length values packed
    into one AVP. Full codec: encoder concatenates on emit, decoder
    splits on receipt based on a wire-length table covering all ten
    fixed-length RADIUS types.
  - ``secret`` — accepted as a no-op marker for parity with FR-internal
    dicts.
- **WiMAX / RFC 5904 long-packed VSAs.** ``VENDOR foo 12345
  format=1,1,c`` is parsed. ``vendor_formats`` widened from
  ``(type_len, len_len)`` to ``(type_len, len_len, has_continuation)``;
  ``vendor_format()`` accessor updated. The same shape is used by
  Telrad.

# Wire encoding / decoding

- **3+ level nested TLV codec.** Walking the parent chain in
  ``add_attribute`` creates nested dicts at every level
  (``self[241][5][1]`` for a ``241.5.1`` leaf). New
  ``_encode_tlv_chain`` flattens any depth into TLV chain bytes; both
  ``_pkt_encode_extended`` and ``_pkt_encode_long_extended`` detect
  dict-valued slots and emit nested chains inside the outer envelope.
  ``_pkt_encode_tlv`` (top-level TLV) handles dict-valued children too.
  On the decode side, ``_decode_tlv_chain_into`` recursively parses
  TLV chains, descending into any child slot the dictionary declares
  as ``tlv``. ``__getitem__`` recurses so
  ``pkt["Wrapper"]["Container"]["Leaf"]`` returns decoded values at
  every depth. 2-level behaviour is unchanged; the chain walk
  degenerates to the old single-parent case.
- **Virtual attribute encoder skip.** ``_pkt_encode_attributes`` now
  consults ``_is_virtual_attribute(code)`` and omits the AVP entirely
  when the dictionary marked it ``virtual``.
- **Array encoder + decoder.** ``_encode_avp_group`` concatenates
  multi-value lists for ``array`` attributes into a single AVP value
  before wrapping. A new ``_split_array_attributes`` runs after
  ``_merge_concat_attributes`` on decode and slices the packed bytes
  into N values based on the type's fixed wire length. Symmetric round
  trip.
- **WiMAX continuation encoder.** ``_pack_vsa_inner`` gains an optional
  ``continuation`` parameter inserted between the length header and the
  value. New ``_pkt_encode_continuation_vsa`` fragments long values
  across multiple AVPs with the ``_VSA_CONTINUATION_MORE`` (0x80) flag
  set on every fragment except the last. Per-fragment payload budget
  is 246 bytes for the standard ``1,1,c`` layout.
- **WiMAX continuation decoder.** ``_pkt_decode_vendor_attribute`` reads
  the cont byte for continuation-format vendors, buffers fragments in
  a per-decode ``_vsa_continuation_buf`` keyed by ``(vendor, atype)``,
  and emits the joined value when More clears.
- **``encode_octets`` no longer hard-caps raw-bytes input at 253
  bytes.** The cap was the AVP layer's responsibility — fragmenting
  attributes (``concat``, RFC 6929 ``long-extended``, RFC 5904
  continuation) legitimately carry longer logical values. The 253 cap
  still applies to ``0x...`` literal input where it catches typos.


- **New ``DROP_NOREPLY`` sentinel** in ``pyrad2.dedup``. When a handler
  raises or silently exits without a reply, the ``_dedup_dispatch``
  finally clause records the sentinel via
  ``ResponseCache.mark_dropped_if_in_flight``. Retransmissions within
  the TTL hit the sentinel and DROP cleanly. The sentinel is
  idempotent with ``record_reply``: a successful handler that
  subsequently records a real reply clears the sentinel, so the no-op
  on the second pass when the cache was already populated stays safe.
- ``ResponseCache.lookup`` and ``consult_cache`` map both ``IN_FLIGHT``
  and ``DROP_NOREPLY`` to ``DispatchAction.DROP``. ``record_reply``
  clears any stale DROP sentinel; ``_evict_locked`` evicts expired
  drop sentinels alongside real cached replies.
- Both sync ``Server`` and ``ServerAsync`` updated. The legacy
  ``dedup_drop_in_flight`` helper is retained for backwards
  compatibility.

# Bug fixes

- **``proxy.py`` fix, broken since refactor.

# Documentation

- **New ``docs/conformance.md``** (linked from ``mkdocs.yml`` Guides
  nav) covering the FreeRADIUS conformance suite — goal, model,
  results, known corner cases.
- **``docs/dictionary.md`` refreshed**: data-types table picked up
  ``ipv4prefix``, ``combo-ip``, ``vsa``; attribute-options table picked
  up ``array``, ``virtual``, ``secret``; ``format=`` section documents
  the ``,c`` continuation; a new "Nested TLVs" section replaces the
  stale "TLV nesting deeper than two levels is not supported" line and
  shows the 3-level syntax + recursive packet access pattern. The
  ``uint8``/``uint16``/``uint32``/``uint64``/``int32`` aliases get a
  short paragraph.
- **``docs/index.md`** "What's in the box" table refined: FreeRADIUS
  dictionary row expanded (nested TLVs, WiMAX continuation, RFC 8044
  arrays); new row for the conformance suite.
- **``pyrad2/dictionary.py`` module docstring** updated: stale
  "Nested TLVs deeper than two levels are not yet supported" removed;
  pointers to the dictionary reference and the new conformance page
  added.

# Migration

3.1 is **fully backwards compatible** with 3.0 for any code that
worked under 3.0:

- Existing dictionaries continue to load (the parser only got more
  permissive; nothing got rejected that previously parsed).
- Existing wire encode/decode produces byte-identical output for
  2-level TLV and standard VSA paths (the nested-TLV chain walk
  degenerates to the prior single-parent case for 2-level codes).
- ``vendor_format()`` returns a 3-tuple instead of a 2-tuple. Code that
  destructures the tuple needs an extra binding (``type_len, len_len,
  has_continuation = …``). The default for vendors without ``,c``
  declared is ``False``, so the third element is benign for legacy
  callers that don't care.
- ``encode_octets`` accepts longer raw-bytes input than before. No
  caller is harmed by relaxed validation; this is strictly a fix for
  long-value fragmenting attributes that the upstream cap was
  silently breaking.


3.0 - 2026-06-02
----------------

This is a **security and defaults overhaul**. Every UDP server / client
in pyrad2 now ships with BlastRADIUS-safe defaults out of the box, RadSec
deployments default to TLS 1.3, and the sync server now verifies request
authenticators before invoking your handlers , matching the long-standing
``ServerAsync`` behaviour. All of these are observable behaviour breaks
for existing deployments; the section below documents each opt-out.

# Security defaults (BREAKING)

- **BlastRADIUS (CVE-2024-3596) mitigated by default.**
  `Server`, `ServerAsync`, `Client`, and `ClientAsync` now default to
  enforcing `Message-Authenticator` on every `Access-Request` and on the
  matching `Access-Accept` / `Reject` / `Challenge` reply. To bridge a
  legacy NAS that doesn't emit the attribute, pass
  `require_message_authenticator=False` (servers) or `enforce_ma=False`
  (clients). Scope is intentionally narrow: `Accounting-Request`,
  `CoA-Request`, and `Disconnect-Request` are unaffected because their
  Request Authenticator MD5 already covers body + secret, and
  `RadSecServer` still defaults to `False` because TLS authenticates the
  transport.
- **Sync `Server` now verifies request authenticators by default.**
  Mirrors `ServerAsync.enable_pkt_verify` which previously was the only
  side that ran the check. Pass `enable_pkt_verify=False` to opt out for
  legacy NASes that emit malformed authenticators.
- **RadSec defaults to TLS 1.3.**
  `RadSecServer.DEFAULT_MINIMUM_TLS_VERSION` and
  `RadSecClient.DEFAULT_MINIMUM_TLS_VERSION` are now
  `ssl.TLSVersion.TLSv1_3` (RFC 9325 deprecates TLS 1.1-, treats 1.2 as
  legacy; RFC 9750 mandates 1.3 for RADIUS/1.1). Pass
  `minimum_tls_version=ssl.TLSVersion.TLSv1_2` to bridge a legacy peer
  that can't yet negotiate 1.3. The floor is auto-promoted to 1.3 when
  `radius_versions` includes `V1_1`, regardless.
- **Constant-time MAC and MD5 comparisons** across the verify path.
  `verify_message_authenticator`, `verify_reply`, `verify_packet`, and
  `AuthPacket.verify_chap_passwd` all switched from `==` to
  `hmac.compare_digest`, closing a timing-side-channel that let an
  off-path attacker probe valid MACs one byte at a time.
- **Zero-authenticator Access-Request rejected.**
  `AuthPacket.verify_auth_request` now rejects v1.0 Access-Requests
  whose Request Authenticator is all-zero (RFC 2865 §3 requires
  unpredictability). `Packet.salt_crypt` no longer falls back to a
  zero authenticator when one is missing , it calls
  `create_authenticator()` so salt-encrypted attributes (Tunnel-Password,
  MS-MPPE keys) can't be recovered without the shared secret.
- **`PYRAD2_TRACE` now requires a second-step acknowledgement.**
  Setting `PYRAD2_TRACE=1` no longer activates the wire trace on its
  own. The trace dumps the Request Authenticator and obfuscated
  `User-Password` bytes; with the shared secret known (commonly to
  anyone reading the log archive), the plaintext is fully recoverable.
  Set `PYRAD2_TRACE_UNSAFE=1` alongside to acknowledge and enable. A
  warning is logged on activation.

# Security hardening

- **`$INCLUDE` sandboxing.** `Dictionary` / `DictFile` now confine
  `$INCLUDE` resolution to a base directory (defaults to the entry-point
  file's parent; configurable via `include_base_dir=`). A dictionary
  with `$INCLUDE /etc/passwd` or `$INCLUDE ../../foo` raises
  `ParseError`. The entry-point file is exempt , it defines the base.
- **`ParseError` signature tightened.** The old `**data` swallow
  silently dropped `name=`, `path=`, and similar typos. The new
  signature explicitly accepts `file=` and `line=`; the filename now
  consistently surfaces in error messages.
- **Vendor-id range check.** `Dictionary` rejects `VENDOR` declarations
  outside `0..0xFFFFFF` (RFC 2865 §5.26 SMI PEN range) instead of
  silently passing through values that later corrupt the VSA encoder.
- **`eap.password_from_packet` no longer falls back to User-Name.**
  Returning `User-Name` as the EAP-MD5 secret silently mis-keyed the
  challenge; any observer who saw the request could reproduce the
  digest. Raises `PacketError` when `User-Password` is absent.
- **`pw_decrypt` warns on shared-secret mismatch.** Non-UTF-8 bytes
  after de-obfuscation almost always indicate the receiver's secret
  doesn't match the sender's. The function now logs a `WARNING` once
  per call and continues with a lossy decode so legacy handlers don't
  crash. (M9)
- **Dedup cache failed-handler behaviour documented.** A handler that
  exits without sending a reply still drops its in-flight marker, so a
  retransmission within the TTL window is processed fresh rather than
  suppressed , bug acknowledged; H6 fix scheduled for 3.1.

# Architecture

- **New `pyrad2.router.RequestRouter`** unifies the dispatch state
  machine that `Server` and `ServerAsync` previously each owned: host
  lookup, secret-aware parse, per-code Request Authenticator
  verification, Message-Authenticator policy (incoming and outgoing),
  and RFC 5080 dedup helpers. Both servers became thin transport
  adapters; `Server` shrank by 109 lines, `ServerAsync` by 173. The
  `ServerType` enum moved to `pyrad2.router` and is re-exported from
  `pyrad2.server_async` for backwards compatibility. As a side effect:
  `Server`'s `_realauthfds` etc. are now sets (O(1) membership check
  per packet) instead of lists.
- **Packet subclass deduplication.** `Packet` gained `_make_reply`,
  `_ensure_id_and_short_circuit_v11`,
  `_encode_v10_request_with_random_authenticator`, and
  `_encode_v10_request_with_body_md5_authenticator`. The four typed
  subclasses (`StatusPacket`, `AuthPacket`, `AcctPacket`, `CoAPacket`)
  each shrank to one-line wrappers over those helpers. Net diff is
  roughly 50 lines smaller; semantics unchanged (CoA's historical
  two-pass Message-Authenticator refresh is now single-pass but
  byte-equivalent on the wire).
- **Cross-client factory deduplication.** New
  `_ClientPacketFactoryMixin` in `pyrad2.host` provides the
  `create_auth_packet` / `create_acct_packet` / `create_coa_packet` /
  `create_status_packet` wrappers shared by `Client`, `ClientAsync`,
  and `RadSecClient`. Each client now declares its id-allocation
  strategy via `_allocate_packet_id(server_type)` and inherits the
  rest. Roughly 100 lines of duplicated boilerplate removed; public
  API unchanged.

# Per-transport identifier management

- **`DatagramProtocolClient.create_id` scans for a free slot** instead
  of blindly returning `(packet_id + 1) % 256`. Raises a new typed
  `IdentifierExhausted` (in `pyrad2.exceptions`) when all 256 slots
  on a single (source IP, source port) flow are in flight. The
  bare-`Exception` collision error in `send_packet` is now also typed.
- **Module-level `CURRENT_ID` is thread-safe.** A `threading.Lock`
  serialises the increment so concurrent `Packet()` construction
  across threads can't read+write the same counter and end up with
  colliding ids.

# Performance

- **RFC 2865 keystream loops rewritten** for `_salt_en_decrypt`,
  `pw_crypt`, and `pw_decrypt`. The byte-at-a-time
  `bytes((hash[i] ^ buf[i],))` concat chain is replaced by an int-XOR
  + `bytearray` accumulator. ~3× faster on User-Password and
  Tunnel-Password sized inputs (5000-iter micro-benchmark, sizes 16
  through 240 bytes). New helper `_md5_keystream_xor(secret, prev,
  block)` is module-level so the three call sites share one
  implementation.
- **Asyncio deprecation cleanup.** Replaced `asyncio.Future(loop=...)`
  / `get_event_loop()` with `get_running_loop().create_future()` at
  all five call sites in `client_async.py`. The 3.12
  DeprecationWarning that printed on every test run is gone.

# DX / quality

- **Sync `Client._send_packet` no longer mutates the caller's
  `Acct-Delay-Time`.** The retry loop still bumps the value while a
  request is in flight, but it now snapshots the caller's original
  list (or absence) and restores it on exit , so reusing the same
  `AcctPacket` across multiple `send_packet` calls no longer
  compounds the delay. (M6)
- **`getaddrinfo` fixes.** Both `Client._socket_open` and
  `Server._get_addr_info` previously resolved against port 80 with
  the default `SOCK_STREAM`, doing a wasted service-name lookup and
  iterating over duplicated TCP+UDP entries. Now `port=None,
  type=socket.SOCK_DGRAM`.
- **Test suite migrated to pytest-style.** All 15 files dropped
  `unittest.TestCase` / `IsolatedAsyncioTestCase`; `setUp` →
  `setup_method`, `assertEqual` → `assert ==`, `assertRaises` →
  `pytest.raises`. `pytest-asyncio` added to dev deps with
  `asyncio_mode = "auto"` configured in `pyproject.toml`. New
  `tests/conftest.py` provides session-scoped `full_dictionary`,
  `simple_dictionary`, `chap_dictionary`, and `radsec_dictionary`
  fixtures (28 of 30 inline `Dictionary(...)` calls migrated to use
  them). 519 tests pass; coverage 85%.
- **CI hygiene.** `python-test.yml` rebuilt as three parallel jobs:
  `lint` (`ruff check` + `ruff format --check`), `typecheck` (`mypy`),
  and `test` (pytest matrix with `--cov-fail-under=80`). Concurrency
  group cancels superseded runs. `uv sync --frozen` enforces the
  lockfile in every job. New `.github/dependabot.yml` schedules
  weekly grouped updates for `pip` and `github-actions`. The
  pre-existing publish workflow was already replaced with
  `uv build` + Trusted Publishing OIDC; CodeQL bumped from `@v1`
  (archived) to `@v3`.
- **Packaging metadata consolidated.** `setup.py` and `setup.cfg`
  deleted. `pyproject.toml` carries the full PEP 639 `license =
  "BSD-3-Clause"` + `license-files = ["LICENSE.txt"]`, full
  classifiers, `dynamic = ["version"]` reading from
  `pyrad2/__init__.py`, and `[build-system]` with hatchling.
- **`example/auth.py` typo fix.** `logger.inferroro(..., error[1])` ,
  the canonical client example couldn't run on any network error ,
  now correctly calls `logger.error("Network error: {}", error)`.
- **Documentation tooling no longer ships to runtime users.**
  `mkdocs-material` and `mkdocstrings[python]` removed from
  `[project].dependencies`; remain in `[dependency-groups].docs`.

# Migration

If you upgrade from 2.5 without code changes, expect:

1. UDP servers will drop `Access-Request` packets that don't carry
   `Message-Authenticator`. Pass `require_message_authenticator=False`
   to restore the old default.
2. UDP clients will refuse `Access-Accept` / `Reject` / `Challenge`
   replies missing `Message-Authenticator`. Pass `enforce_ma=False`.
3. `Server` will reject packets whose Request Authenticator fails MD5
   verification. Pass `enable_pkt_verify=False`.
4. `RadSecServer` / `RadSecClient` won't accept TLS 1.2 connections
   unless you pass `minimum_tls_version=ssl.TLSVersion.TLSv1_2`.
5. Existing log pipelines watching for `[pyrad2 trace]` lines on
   `PYRAD2_TRACE=1` will go silent until `PYRAD2_TRACE_UNSAFE=1` is
   also set.


2.4 - 2026-05-17
----------------

# Deduplication (RFC 5080)

- RFC 5080 §2.2.2 duplicate detection and response cache for `Server` and
  `ServerAsync`. Retransmitted Access/Accounting/CoA/Disconnect-Requests now
  replay the original reply bytes instead of re-running the handler , critical
  for EAP `State` continuity and to avoid double-counting accounting updates.
  Enabled by default; tune via `dedup_enabled`, `dedup_ttl`, `dedup_max_entries`,
  or `dedup_cache=` on the server constructor.

# RADIUS/1.1 (RFC 9765, experimental)

- New protocol profile selected via TLS ALPN (`radius/1.1` vs `radius/1.0`).
  `RadSecServer` and `RadSecClient` accept `radius_versions=...` to advertise
  the new ALPN protocol; the default `(V1_0,)` preserves byte-identical
  handshake behavior with historic RadSec deployments.
- When `radius/1.1` is negotiated the connection drops all MD5 baggage ,
  no User-Password / Tunnel-Password / MS-MPPE obfuscation, no
  Message-Authenticator, no Response Authenticator MD5. A per-connection
  32-bit Token replaces the Request/Response Authenticator; the Identifier
  byte is zero on the wire.
- TLS 1.3 floor (RFC 9765 §3.4) auto-applied when v1.1 is configured.
- Strict mode (`radius_versions=(V1_1,)`) refuses to silently downgrade
  (RFC 9765 §3.3): server closes the TLS connection, client raises a
  clean `PacketError` and `send_packet` returns `None`.
- New `Packet.set_obfuscated(name, plaintext)` defers password encoding
  until send time so dual-advertise clients don't have to know the
  negotiated version at attribute-assignment time. Covers User-Password
  and any `encrypt=2` attribute (Tunnel-Password, MS-MPPE keys).
- A separate `Packet.token` slot replaces the previous
  Token-in-authenticator hack so a prior `pw_crypt()` on a packet can no
  longer leak random bytes into the v1.1 Reserved-2 region (RFC 9765 §4.1).
- Incoming v1.1 packets silently discard any received Message-Authenticator
  attribute (RFC 9765 §5.2) , handlers never observe it.
- ``Packet.set_obfuscated`` is now idempotent across serializations: the
  plaintext sidecar remains the source of truth so a re-encode under a
  different negotiated version (e.g. a retry after a reconnect that
  resumed under a different ALPN) emits the correct ciphertext or
  plaintext rather than replaying stale bytes from the first send.
- The five copies of the v1.1 emission path collapse into a single
  ``Packet._serialize_v11()`` helper.
- ``_pack_v11_header`` now raises ``PacketError`` if the Token is missing
  or the wrong size, with an explicit ``zero_token=True`` opt-in for
  Protocol-Error replies (RFC 9765 §6.1).
- ``RadSecClient.last_error`` exposes the failing exception after a
  ``send_packet`` returns ``None``, so a strict-mode ALPN refusal is
  distinguishable from a normal timeout. Negotiation errors log under a
  distinct ``RADSEC negotiation failure`` tag.
- ``RadSecClient._stamp_radius_version`` now always overwrites
  ``packet.radius_version`` and clears ``packet.token`` on v1.0
  negotiation, so a reused packet that was previously serialized under
  v1.1 doesn't leak a Token / zero Identifier / plaintext password onto
  the v1.0 wire when a reconnect drops the negotiation back.
- ``StatusPacket.verify_status_request`` (new) replaces the inline
  Message-Authenticator check in ``RadSecServer._verify_packet``;
  RADIUS/1.1 Status-Server packets no longer get rejected by a
  ``verify_packet=True`` server (RFC 9765 §5.2 forbids the AVP).
- ``AuthPacket.verify_chap_passwd`` raises ``PacketError`` in RADIUS/1.1
  when ``CHAP-Challenge`` is absent (RFC 9765 §5.1.2). Previously it
  silently synthesized a random authenticator and "failed closed" for
  the wrong reason.
- Serialization is now side-effect free. The deferred-obfuscation
  sidecar is encoded inline at ``_pkt_encode_attributes`` time rather
  than by deleting and re-adding entries on ``self`` , repeated
  ``request_packet()`` calls leave the packet's stored attribute map
  byte-stable.
- v1.1 request serializers no longer seed ``self.authenticator`` via
  ``create_authenticator()`` before taking the v1.1 branch , v1.1
  packets carry no misleading legacy state.
- ``set_obfuscated`` now reuses the same per-AVP container dispatch the
  main encoder uses (``_encode_avp_group``). That preserves whatever
  framing the dictionary defines , plain top-level, Vendor-Specific
  (RADIUS attribute 26), TLV nested under its parent code, EVS 4-tuple
  routed through the extended-attribute encoder, or extended /
  long-extended fragmentation. Previously the deferred path bypassed
  this dispatch and emitted bare top-level AVPs, mis-encoding (e.g.)
  MS-MPPE-Recv-Key as RADIUS-17 (Reply-Message) and crashing on EVS
  4-tuple keys with a tuple-unpack error. Tag-prefixed names
  (e.g. ``Tunnel-Password:1``) are honored on the deferred path with
  the same byte layout as direct assignment. Mixing a deferred TLV /
  extended sub-attribute with directly-assigned siblings under the
  same container parent is now merged correctly , non-deferred
  siblings ride on the wire alongside the deferred ones rather than
  being silently dropped.
- New module `pyrad2.radsec.v11`: `RadiusVersion`, `apply_alpn`,
  `negotiate`, `NoCommonRadiusVersion`, `enforce_tls_version_floor`,
  `TokenCounter`.
- New scenario `scenarios/radsec_v11.py` and `make scenario_radsec_v11`.

2.2 - May 17, 2025
------------------

- Add scenarios for a better development experience.
- Add support for Extended attributes (types 241–244) and Long-Extended attributes (types 245–246)
- Add support for RFC 6929
- Add support for EVS (Extended-Vendor-Specific) attributes
- BEGIN-VENDOR <name> parent=<evs-attr> now accepted
- Add encoders/decoders for ifid (RFC 3162) and ether (RFC 6911)

2.1 - May 16, 2025
------------------

# Breaking Changes (RadSec onyly)
  - Default flips: deployments on TLS 1.1 or with non-matching cert SANs now fail. Pass custom config to avoid this behaviour.
  - Stricter MA + connection reuse default. Peers sending malformed MAs are now rejected. Use `reuse_connection=False` to disable it.

- RadSec client now defaults to hostname validation and TLS 1.2+
- RadSec server now defaults to mutual TLS client-cert verification and TLS 1.2+
- Removed the hard-coded legacy cipher list path
- Callers can still pass a custom OpenSSL cipher string explicitly
- Added SHA-256 certificate fingerprint normalization/matching helper
- Added optional server certificate and client certificate fingerprint allowlists
- RadSecServer(verify_packet=True) now dispatches to the correct packet verifier
- Updated RadSec server handling to read packets in a loop on each TLS connection instead of processing only one packet
- Added configurable connection_read_timeout and max_packets_per_connection
- RadSec client to reuse one TLS connection by default
- Added configurable client options for reuse_connection=False for old one-connection-per-packet behavior
- Added reconnect_backoff
- Existing timeout now wraps connect, write/drain, and response
- Added close() and async context-manager support for reusable RadSec clients
- RadSecServer no longer requires handle_coa() or handle_disconnect() either
- RadSec now has enable_coa and enable_disconnect flags. They default to True for compatibility, but disabled requests get NAKed cleanly

# Message Authenticator

- Fix reply Message-Authenticator verification to validate the reply, not the request
- Validate Message-Authenticator whenever the attribute is present
- Require Message-Authenticator for packets containing EAP-Message
- Add opt-in server policy to require Message-Authenticator on all packets
- Automatically add Message-Authenticator to EAP requests and protected replies

# Status-Server

- Add StatusPacket creation and parsing
- Add sync, async, and RadSec Status-Server handling
- Require Message-Authenticator on Status-Server requests
- Reply to auth Status-Server checks with Access-Accept
- Reply to accounting Status-Server checks with Accounting-Response
- Avoid invoking normal auth/accounting handlers for health checks
- Add UDP and RadSec status examples
- Document Status-Server usage across client and server APIs

# Improvements to COA and Disconnect

- ServerAsync no longer requires handle_coa_packet() or handle_disconnect_packet() on every subclass
- Default UDP async behavior now replies with CoA-NAK or Disconnect-NAK
- RadSecServer no longer requires handle_coa() or handle_disconnect() either
- RadSec now has enable_coa and enable_disconnect flags. They default to True for compatibility, but disabled requests get NAKed cleanly
- NAKs include RFC 5176 Error-Cause = 406 / Unsupported Extension

# Feature Parity

- Fix async client retry/timeout correctness and add EAP-MD5 parity The async retry loop in client_async.py had two latent bugs and lagged the sync client on EAP-MD5 handling. Both bugs were silently invisible because no test covered the retry path.
- Retries raised AttributeError inside an asyncio task and never re-sent on the wire. Changed to request_packet() to match the initial send.
- Fixed timeout math
- EAP-MD5 added to async client and all 3 clients (sync, async and radsec) call the same shared helper

2.0 - Apr 6, 2026
-----------------

- *Breaking Changes*: The entire codebase has been converted from CamaleCase to use Python's snake case.
- Enforce Message-Authenticator if present
- Ascend-Data-Filter now supports `delete` keyword
- Several fixes, more typing

# Breaking Changes

- Converted BiDict to Python standard

1.2.0 - Jul 22, 2025
--------------------

# Features

- Use selectors in place of select on Windows

1.1.1 - Jul 9, 2025
--------------------

# Fixes

- `ssl.CERT_REQUIRED` is enabled by default.

1.1.0 - Jul 9, 2025
--------------------

# Features

- add RadSec (RFC 6614) support. _Experimental_
- Ensure all examples in the `examples` folder are working.

# Refactors

- Move constants to `pyrad2.constants`
- Move several global variables into `pyrad2.constants`.
- EAP and Packet types are now acessed via PacketType enum in `constants` module. 
- `DATATYPES` has moved to `constants.py`
- Consolidate all exceptions under `exceptions.py`. All of the libraries exceptions inherit from `RadiusException` now.

# Testing

- Improve typing and testing coverage.


# Documentation

- Improve navigation.
- Add RadSec pages.

# Chore

- Add several testing options to Makefile.
- Add test/example SSL certificates for server and client.

1.0 - Jul 7, 2025
-------------------

- Extensively refactored code
- Remove legacy Python 2.x/3.x and support only Python 3.12
- Add typing support to the whole codebase using mypy.
- Poetry phased out in favour of uv
- [#213](https://github.com/pyradius/pyrad/pull/213) in PyRad fixed.
- [#210](https://github.com/pyradius/pyrad/pull/210) in PyRad merged.
- Remove `nose` as it's unmaintained and replace it with pytest. `pytest-sugar` being used for pretty test output.
- Added loguru dependency for better log formatting.
- Modernize AsyncIO code.
- Update README.md
