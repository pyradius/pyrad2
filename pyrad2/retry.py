"""Shared retransmission policy for the sync and async RADIUS clients.

RADIUS retransmission timing is left to the implementation by RFC 5080
§2.2.1; both clients historically used a flat, jitter-free schedule
(``timeout`` seconds between every retry). ``RetryPolicy`` keeps that
schedule as its default but lets a caller layer exponential backoff and
jitter on top — the same object is consumed by ``Client`` (sync) and
``ClientAsync``.
"""

from dataclasses import dataclass, replace
import random


@dataclass(frozen=True)
class RetryPolicy:
    """How long a client waits between retransmissions.

    Attributes:
        retries: Maximum number of retransmissions before giving up. The
            initial send is *not* counted — ``retries=3`` means up to one
            send and three retries, i.e. four packets on the wire worst
            case.
        timeout: Base wait, in seconds, before the first retry.
        backoff: Multiplicative growth applied per retry. ``1.0``
            preserves the legacy flat schedule; ``2.0`` doubles each
            wait (5s, 10s, 20s, …).
        jitter: Fractional uniform noise applied to each computed wait,
            sampled from ``U(-jitter, +jitter) * wait``. ``0.1`` adds
            ±10%. Used to break lockstep retransmission across many
            clients sharing a server.
        max_wait: Hard ceiling, in seconds, on any single wait. Prevents
            a high backoff from producing pathologically long waits.
    """

    retries: int = 3
    timeout: float = 5.0
    backoff: float = 1.0
    jitter: float = 0.0
    max_wait: float = 30.0

    def wait_for(self, attempt: int) -> float:
        """Return the wait, in seconds, before retry number ``attempt``.

        ``attempt`` is the count of retries already performed for this
        request — ``0`` is the wait between the initial send and the
        first retry, ``1`` is the wait between the first and second
        retry, and so on.
        """
        wait = min(self.timeout * (self.backoff**attempt), self.max_wait)
        if self.jitter:
            wait += wait * random.uniform(-self.jitter, self.jitter)
            wait = max(0.0, wait)
        return wait


class _LegacyAttrMixin:
    """Property proxies so ``self.retries`` / ``self.timeout`` stay live.

    Tests and downstream callers historically mutate ``client.retries``
    and ``client.timeout`` directly after construction. The shared
    ``RetryPolicy`` is frozen, so each setter rebuilds the underlying
    policy via :func:`dataclasses.replace` to keep the loop's source of
    truth consistent with the legacy attribute names.
    """

    retry_policy: RetryPolicy

    @property
    def retries(self) -> int:
        return self.retry_policy.retries

    @retries.setter
    def retries(self, value: int) -> None:
        self.retry_policy = replace(self.retry_policy, retries=int(value))

    @property
    def timeout(self) -> float:
        return self.retry_policy.timeout

    @timeout.setter
    def timeout(self, value: float) -> None:
        self.retry_policy = replace(self.retry_policy, timeout=float(value))


def policy_from_legacy(
    retry_policy: "RetryPolicy | None",
    retries: int,
    timeout: float,
) -> RetryPolicy:
    """Resolve constructor arguments into a single ``RetryPolicy``.

    Bridges the historical ``retries=`` / ``timeout=`` keyword pair with
    the newer ``retry_policy=`` argument so both clients can share one
    code path. An explicit ``retry_policy`` always wins; otherwise a
    flat (no backoff, no jitter) policy is built from the legacy args.
    """
    if retry_policy is not None:
        return retry_policy
    return RetryPolicy(retries=retries, timeout=float(timeout))
