
⏺ Remaining findings (C1–C5 already addressed)

  High

  H1 — Module-level non-thread-safe CURRENT_ID
  packet.py:91, 2016-2025: a process-global identifier counter shared across threads/asyncio tasks; concurrent clients in the same process can collide on id, mismatching replies. Move identity tracking onto the
  client/transport.

  H2 — create_authenticator does 16 SystemRandom syscalls
  packet.py:881: bytes(random_generator.randrange(0, 256) for _ in range(16)). One secrets.token_bytes(16) does the same job ~16× faster.

  H3 — O(N²) password/salt obfuscation hot loops
  packet.py:1457-1472, 1735-1739, 1785-1789: result += bytes((hash[i] ^ buf[i],)) then last = result[-16:]. Single-byte bytes() allocations and string concat. Fix: integer XOR or bytes(x ^ y for x, y in zip(hash,
   buf)) + bytearray. Hot path on every Access-Request.

  H4 — Sync server _process_input does linear scans of fd lists per packet
  server.py:436-450: fd.fileno() in self._realauthfds (lists). Build sets in _prepare_sockets. Same for acct/coa.

  H5 — Dedup cache: single lock, RLock, eager eviction every record
  dedup.py:115,164: replace RLock with Lock (no recursion); call _clock() once per record_reply; shard the cache for high-QPS deployments.

  H6 — Dedup cache: failed handlers leave no "drop" entry
  server.py:271-278 / server_async.py:373-379: on handler exception or silent drop, the finally removes the in-flight marker; the next retransmission is processed again. Record a "drop" sentinel for at least one
  TTL to preserve RFC 5080 semantics.

  H8 — TLS 1.2 default in RadSec
  radsec/client.py:32, radsec/server.py:60: DEFAULT_MINIMUM_TLS_VERSION = TLSv1_2. RFC 9750 (RADIUS/1.1) requires TLS 1.3; modern guidance is 1.3 unconditionally. Default to 1.3, allow opt-down only via explicit
  kwarg.

  H10 — Async client identifier exhaustion is a bare Exception
  client_async.py:201-203. Raise typed IdentifierExhausted; queue or rotate source ports.

  H11 — Hardcoded port 80 in getaddrinfo
  client.py:87 and server.py:166 resolve with port 80 (and even SOCK_STREAM by default). Wrong service, wasted work. Use port=None, type=socket.SOCK_DGRAM.

  H12 — dictionary.py errors lose the filename
  dictionary.py:213 calls ParseError(name=state["file"], ...) but ParseError.__init__ only reads file/line from **data. Filename is silently dropped. Tighten ParseError to explicit kwargs; rename name= → file=.

  H13 — eap.password_from_packet silently falls back to User-Name
  eap.py:65-69: if no User-Password, the username is used as the secret for the EAP-MD5 challenge. Auth silently degrades. Raise instead.

  H14 — tools.encode_octets accepts ambiguous decimal strings
  tools.py:29-54: a decimal string "256" silently becomes 2 bytes; the documented size check is on the hex string length, not the decoded length. Tighten contract: accept bytes or "0x..." hex only.

  H15 — Publish workflow is broken / will start failing
  .github/workflows/python-publish.yml:25-30 uses setup.py sdist bdist_wheel + PYPI_USERNAME/PASSWORD; PyPI now requires API tokens or Trusted Publishing.
  .github/workflows/codeql-analysis.yml:46,57: CodeQL @v1 is archived and will fail. Bump to @v3.

  ▎ (H7, H9 are absorbed by C5 / C2.)

  Medium

  M1 — Duplication across sync/async server dispatch
  server.py:294-350 vs server_async.py:86-167, plus duplicated status-server handling and create_reply_packet. Extract a RequestRouter shared by both; that single refactor also closes H4, H10 and removes the dead
   branch in ServerAsync.create_reply_packet (server_async.py:449-455).

  M2 — Packet subclass boilerplate
  AuthPacket, AcctPacket, CoAPacket, StatusPacket each duplicate __init__, create_reply, request_packet. The MD5-authenticator computation is open-coded 4×. Factor a _authenticate_request helper and parameterize
  by reply code.

  M3 — Three client implementations duplicate factory methods
  client.py, client_async.py, radsec/client.py each redefine create_auth_packet / create_acct_packet / create_coa_packet / create_status_packet / EAP-MD5 round-trip. Move to a single mixin.

  M4 — tools.py encode/decode tables
  25-branch if/elif chains (tools.py:339-404) — replace with a dict[str, (encode, decode, fmt)]. Also merges encode_integer/encode_integer64, decode_integer/decode_integer64/decode_date, and the IPv6 dispatch
  duplication.

  M5 — Async client uses deprecated asyncio.Future(loop=...) and get_event_loop()
  client_async.py:474,505,536,539,571. Use asyncio.get_running_loop().create_future(). Python 3.12 already prints DeprecationWarning.

  M6 — Sync client AccountingRequest retry mutates Acct-Delay-Time on caller's packet
  client.py:182-186. Snapshot and restore.

  M7 — _handle_client has no idle timeout on the first packet
  radsec/server.py:287-298. An idle TLS connection that never sends bytes is bounded only by kernel keepalive. Apply connection_read_timeout to the first read; consider a per-peer concurrent connection cap.

  M8 — reuse_port=True unconditional
  client_async.py:306,327,347. Not portable to Windows; older Linux kernels may need privilege. Make optional.

  M9 — pw_decrypt uses errors="ignore" silently on shared-secret mismatch
  packet.py:1750. Operator gets a garbled password with no signal. At minimum log a warning; ideally raise if the trailing pad pattern is wrong.

  M10 — PYRAD2_TRACE=1 logs raw packet bytes & decoded attributes
  packet.py:28-85. Combined with a known shared secret, the dumped Request Authenticator + obfuscated User-Password lets a log reader recover the plaintext. Add a prominent warning in the docstring and refuse to
  enable in production unless PYRAD2_TRACE_UNSAFE=1 (or similar two-step gate).

  M11 — Dictionary parser misses 0 ≤ vendor_id ≤ 0xFFFFFF validation
  dictionary.py:404. int(vendor, 0) accepts negatives and 64-bit-wide values that later corrupt the VSA encoder. Validate.

  M12 — BiDict.add allows silent collisions
  bidict.py:33-36. Two VALUE lines with the same name silently desync forward/backward maps. Add an existing → raise guard or document it.

  M13 — eap.py numeric constants duplicate the dictionary's authoritative codes
  Move EAP_MESSAGE_ATTR = 79, etc. into pyrad2/constants.py.

  M14 — Mypy/pytest pinned to versions that don't exist
  pyproject.toml:15-17: mypy>=2.1.0, pytest>=9.0.3, pytest-cov>=7.1.0. Today the latest are mypy 1.x, pytest 8.x, pytest-cov 5.x. uv sync --group dev will fail. Pin to real ranges.

  M15 — Author/license/version drift
  Author in pyrad2/__init__.py:1 is nicholas@bloomshield.ee but README and setup.py cite nicholas@santos.ee. Version lives in pyrad2/__init__.py, setup.py, pyproject.toml. Delete setup.py/setup.cfg, declare
  [build-system] + dynamic = ["version"] using Hatch, add license = "BSD-3-Clause" and license-files = ["LICENSE.txt"] per PEP 639.

  M16 — CI never runs ruff/mypy
  .github/workflows/python-test.yml only runs pytest. Add uv run ruff check, uv run ruff format --check, uv run mypy pyrad2. Add concurrency group, Dependabot, pip-audit.

  M17 — Tests are unittest-style despite pytest tooling
  tests/test_packet.py:17,25,77. Loses fixtures/parametrize/sugar.

  M18 — pre-commit ruff v0.11.13 vs dev-group >=0.15.3
  .pre-commit-config.yaml:9. Sync via pre-commit-uv to avoid drift.

  M-runtime-deps — mkdocs-material and mkdocstrings[python] shipped as runtime deps
  pyproject.toml:7-11. Every pip install pyrad2 user pulls hundreds of MB of docs tooling. Move both to [dependency-groups].docs.

  M-example-typo — examples/auth.py:34 has logger.inferroro(...) plus error[1]
  The flagship example crashes on any network error. Fix to logger.error("Network error: {}", error).

  M-include-traversal — Dictionary $INCLUDE allows arbitrary file reads
  dictfile.py:55-67. open(fname) with no path confinement; supports $INCLUDE /etc/passwd and ../../. Confine to a base dir; use a context manager; reject absolute paths unless explicitly allowed.

  M-wildcard-secret — hosts["0.0.0.0"] wildcard secret + default b"radsec"
  radsec/client.py:36-46 ship b"radsec" as the default; radsec/server.py:377 falls back to a single shared secret for any peer that authenticated TLS. Combined: a stolen client cert + default config authenticates
   as anyone. Refuse to start with the literal b"radsec" unless TLS ≥ 1.3 and explicit opt-in.

  Low / Info

  - Proxy (pyrad2/proxy.py) is hardcoded to IPv4, never binds, has no extension hook for actual forwarding; the _handle_proxy_packet callback is missing. Either implement it or delete the class.
  - Server.__init__ shadows builtin dict (server.py:63); rename to dictionary (keep alias for one release).
  - Async server's data[0] dispatch vs sync's pkt.code dispatch (related to M1).
  - Server accepts PacketType.AccountingResponse on the accounting listener (server.py:325-331). That's a reply; reject on the request socket.
  - Twisted example uses mutable default args (examples/twisted_server.py:23) and the file itself notes Twisted is unsupported — delete it.
  - examples/server.py:52 uses magic 45 instead of PacketType.DisconnectNAK.
  - dictionary.py:177 types attributes as dict[Hashable, Any] but the docstring claims BiDict — fix one.
  - Optional/Dict/Hashable imports from typing throughout — project targets 3.12, use built-ins / collections.abc.
  - dictfile.py:113 next = __next__  # BBB for python <3 — delete.
  - Logger uses + str(err) in several spots (server.py:475-489) — use loguru placeholders for structured fields.
  - get_cert_fingerprint in tools.py does a needless PEM↔DER round-trip; hash the DER directly.

  - Async server's data[0] dispatch vs sync's pkt.code dispatch (related to M1).
  - Server accepts PacketType.AccountingResponse on the accounting listener (server.py:325-331). That's a reply; reject on the request socket.
  - Twisted example uses mutable default args (examples/twisted_server.py:23) and the file itself notes Twisted is unsupported — delete it.
  - examples/server.py:52 uses magic 45 instead of PacketType.DisconnectNAK.
  - dictionary.py:177 types attributes as dict[Hashable, Any] but the docstring claims BiDict — fix one.
  - Optional/Dict/Hashable imports from typing throughout — project targets 3.12, use built-ins / collections.abc.
  - dictfile.py:113 next = __next__  # BBB for python <3 — delete.
  - Logger uses + str(err) in several spots (server.py:475-489) — use loguru placeholders for structured fields.
  - get_cert_fingerprint in tools.py does a needless PEM↔DER round-trip; hash the DER directly.

  Recommended order of attack

  1. M-runtime-deps + M-example-typo + M14 + M15 + H15 (one packaging cleanup PR — drop docs deps, fix the inferroro typo, fix the dep pins, consolidate metadata, fix CodeQL @v1 + publish workflow). Mostly
  mechanical, unblocks a working release.
  2. M-include-traversal + H12 + H13 + M11 (dictionary/EAP parser hardening — path traversal, error metadata, EAP-MD5 silent degradation, vendor-id range check). One small PR.
  3. M-wildcard-secret + H8 (RadSec defaults — refuse b"radsec" literal as the default secret; default TLS to 1.3). One PR.
  4. H3 (perf hot loops in pw_crypt/salt) — easy 5–10× speedup on Access-Request.
  5. M1 (server router refactor) — collapses sync/async drift, removes the dead branch in ServerAsync.create_reply_packet, and unlocks H4, H6, and consistent enable_pkt_verify/Status-Server handling. This is the
  highest-leverage refactor still on the table.
  6. H1 + H10 (identifier management) — per-client/per-transport ID counter, typed IdentifierExhausted exception.
  7. M5 (asyncio deprecations) — small, removes 3.12 DeprecationWarning.
  8. M2 + M3 (sub-class / cross-client duplication) — refactor for clarity; modest size, big readability win.
  9. M4 (tools encode/decode tables) — perf + duplication win, low risk.
  10. Everything else as opportunistic cleanups (the Low/Info list).

  Top single takeaway: with C1–C5 landed, the most user-visible improvements left are the packaging cleanup (#1) and the server-side RequestRouter refactor (M1). The packaging items are mechanical and unblock a
  release; M1 collapses the sync/async drift and absorbs several of the remaining mid-priority findings in one move.