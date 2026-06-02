"""RFC 5080 §2.2.2 duplicate detection and response cache.

A RADIUS server MUST detect duplicate requests and resend the original
response without re-running the handler. The duplicate key is
``(src IP, src UDP port, code, Identifier, Request Authenticator)``.

The cache here is in-memory only (RFC 5080 permits dropping state on
restart). Entries are evicted on TTL expiry or when the LRU cap is hit.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Optional

from pyrad2.constants import PacketType

# Codes for which RFC 5080 dedup applies. Replies (Access-Accept etc.) and
# Status-Server packets are explicitly excluded.
_DEDUPABLE_CODES: frozenset[int] = frozenset(
    {
        PacketType.AccessRequest,
        PacketType.AccountingRequest,
        PacketType.CoARequest,
        PacketType.DisconnectRequest,
    }
)


@dataclass(frozen=True, slots=True)
class DedupKey:
    """RFC 5080 §2.2.2 duplicate-detection tuple."""

    src_ip: Any
    src_port: Any
    code: int
    identifier: int
    request_authenticator: bytes


# Sentinel returned by ``ResponseCache.lookup`` when the original request
# is still being processed by the handler.
class _InFlight:
    __slots__ = ()

    def __repr__(self) -> str:
        return "IN_FLIGHT"


IN_FLIGHT = _InFlight()


class DispatchAction(IntEnum):
    """Outcome of consulting the response cache for an incoming request."""

    PROCESS = 0  # No cache hit. Caller should run the handler.
    DROP = 1  # Duplicate of an in-flight request. Drop silently.
    RESENT = 2  # Cached reply was found and replayed by ``consult_cache``.


def key_for(pkt: Any, source: Any = None) -> Optional[DedupKey]:
    """Build the RFC 5080 dedup key for ``pkt`` or return ``None``.

    ``source`` defaults to ``pkt.source``; pass it explicitly for the
    async server which keeps the address alongside the packet rather
    than on it.

    Returns ``None`` for packet shapes that don't carry the fields we need
    (e.g. unit-test stand-ins) or for codes the spec excludes from dedup.
    """
    code = getattr(pkt, "code", None)
    if code is None or int(code) not in _DEDUPABLE_CODES:
        return None
    src = source if source is not None else getattr(pkt, "source", None)
    if not src or len(src) < 2:
        return None
    # RFC 9765 §4.1: in RADIUS/1.1 the Request Authenticator is replaced
    # by a 4-byte Token. Dedup keys on whichever field carries the
    # client-chosen correlator: token first (v1.1), authenticator
    # otherwise (v1.0).
    correlator = getattr(pkt, "token", None) or getattr(pkt, "authenticator", None)
    if not correlator:
        return None
    ident = getattr(pkt, "id", None)
    if ident is None:
        return None
    return DedupKey(src[0], src[1], int(code), int(ident), bytes(correlator))


class ResponseCache:
    """LRU+TTL cache of reply bytes keyed by ``DedupKey``.

    Thread-safe so it can be shared between the sync server's main loop
    and any worker threads a subclass may use. The async server reuses
    the same class without contention.
    """

    def __init__(
        self,
        ttl: float = 30.0,
        max_entries: int = 4096,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.ttl = ttl
        self.max_entries = max_entries
        self._clock = clock
        self._lock = threading.RLock()
        self._in_flight: set[DedupKey] = set()
        # OrderedDict ordered by recency of insert/refresh — newest at end.
        self._cached: "OrderedDict[DedupKey, tuple[bytes, float]]" = OrderedDict()

    def lookup(self, key: DedupKey):
        """Return cached reply bytes, the IN_FLIGHT sentinel, or ``None``."""
        with self._lock:
            entry = self._cached.get(key)
            if entry is not None:
                raw, expires_at = entry
                if self._clock() < expires_at:
                    self._cached.move_to_end(key)
                    return raw
                del self._cached[key]
            if key in self._in_flight:
                return IN_FLIGHT
            return None

    def mark_in_flight(self, key: DedupKey) -> None:
        with self._lock:
            self._in_flight.add(key)

    def drop_in_flight(self, key: DedupKey) -> None:
        with self._lock:
            self._in_flight.discard(key)

    def record_reply(
        self, key: DedupKey, raw: bytes, ttl: Optional[float] = None
    ) -> None:
        """Atomically transition the entry from in-flight to cached."""
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError("raw must be bytes")
        expires_at = self._clock() + (self.ttl if ttl is None else ttl)
        with self._lock:
            self._in_flight.discard(key)
            self._cached[key] = (bytes(raw), expires_at)
            self._cached.move_to_end(key)
            self._evict_locked()

    def clear(self) -> None:
        with self._lock:
            self._cached.clear()
            self._in_flight.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cached)

    def _evict_locked(self) -> None:
        now = self._clock()
        # Drop expired entries from the front (oldest).
        while self._cached:
            key, (_, expires_at) = next(iter(self._cached.items()))
            if expires_at > now:
                break
            del self._cached[key]
        # Enforce the LRU cap.
        while len(self._cached) > self.max_entries:
            self._cached.popitem(last=False)


def consult_cache(
    cache: Optional[ResponseCache],
    key: Optional[DedupKey],
    resend: Callable[[bytes], None],
) -> DispatchAction:
    """Single point of policy for the dedup state machine.

    Returns one of:

    - ``PROCESS`` if the caller should run the handler. The key is marked
      in-flight before returning, so retries that arrive while the
      handler is still running are dropped.
    - ``DROP`` if a duplicate arrived while the original is in-flight.
    - ``RESENT`` if a cached reply was found; ``resend(raw_bytes)`` has
      already been invoked.
    """
    if cache is None or key is None:
        return DispatchAction.PROCESS
    entry = cache.lookup(key)
    if entry is IN_FLIGHT:
        return DispatchAction.DROP
    if entry is not None:
        resend(entry)  # type: ignore[arg-type]
        return DispatchAction.RESENT
    cache.mark_in_flight(key)
    return DispatchAction.PROCESS


def record_if_keyed(cache: Optional[ResponseCache], reply: Any, raw: bytes) -> None:
    """Cache ``raw`` if the reply carries a dedup key from its request."""
    key = getattr(reply, "_dedup_key", None)
    if key is not None and cache is not None:
        cache.record_reply(key, raw)
