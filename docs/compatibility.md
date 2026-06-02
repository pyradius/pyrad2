# Migrating from pyrad

pyrad2 is a friendly fork of [pyrad](https://github.com/pyradius/pyrad). It is **not** a drop-in replacement.

## Breaking changes since 2.0

- **Python 3.12 or newer** is required.
- **Twisted integration is gone.** Use the asyncio-based `ServerAsync` / `ClientAsync` instead.
- **The entire codebase is snake_case.** PascalCase method names like `CreateAuthPacket` have been renamed to `create_auth_packet`. Adapt your call sites accordingly.
- **BlastRADIUS-safe defaults.** `Server`, `ServerAsync`, `Client`, and `ClientAsync` now default to enforcing `Message-Authenticator` on `Access-Request` and on Access replies (CVE-2024-3596 mitigation). If you talk to a legacy NAS or server that can't emit the attribute, pass `require_message_authenticator=False` (servers) or `enforce_ma=False` (clients) explicitly. The default scope is narrow: `Accounting-Request`, `CoA-Request`, and `Disconnect-Request` are unaffected because they carry their own MD5 authenticator over body + secret, and `RadSecServer` still defaults to `False` because TLS already authenticates origin and integrity.
- **Sync server verifies request authenticators by default.** `Server` now mirrors `ServerAsync.enable_pkt_verify` and defaults it to `True`, dropping packets whose Request Authenticator doesn't match before invoking your handler. Pass `enable_pkt_verify=False` to opt out for legacy NASes that emit malformed authenticators.
- **RadSec defaults to TLS 1.3.** `RadSecServer.DEFAULT_MINIMUM_TLS_VERSION` and `RadSecClient.DEFAULT_MINIMUM_TLS_VERSION` are now `ssl.TLSVersion.TLSv1_3` ([RFC 9325](https://datatracker.ietf.org/doc/html/rfc9325) treats 1.2 as legacy; [RFC 9750](https://datatracker.ietf.org/doc/html/rfc9750) mandates 1.3 for RADIUS/1.1). To bridge a legacy peer that can't yet negotiate 1.3 on a pure v1.0 deployment, pass `minimum_tls_version=ssl.TLSVersion.TLSv1_2` explicitly. If `radius_versions` includes `V1_1`, the floor is promoted back to 1.3 regardless.

For everything new in the fork (RadSec, RADIUS/1.1, Status-Server, dedup, Message-Authenticator enforcement, FreeRADIUS dictionary fidelity, `PYRAD2_TRACE`), see the [home page](index.md) or the [release notes](https://github.com/pyradius/pyrad2/releases).
