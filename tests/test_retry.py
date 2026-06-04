"""Unit tests for the shared ``RetryPolicy`` and its legacy-attr proxy.

These don't exercise the network path — that's covered by
``test_client.py`` and ``test_client_async.py``. The aim here is to lock
down the wait-schedule math and the mutability shim that keeps
``client.retries = N`` / ``client.timeout = N`` working after the move
to the frozen-dataclass policy.
"""

import random

from pyrad2.retry import RetryPolicy, policy_from_legacy


class TestRetryPolicy:
    def test_flat_schedule_returns_constant_wait(self):
        policy = RetryPolicy(retries=3, timeout=5.0)
        assert policy.wait_for(0) == 5.0
        assert policy.wait_for(1) == 5.0
        assert policy.wait_for(2) == 5.0

    def test_exponential_backoff(self):
        policy = RetryPolicy(retries=4, timeout=1.0, backoff=2.0, max_wait=100.0)
        assert policy.wait_for(0) == 1.0
        assert policy.wait_for(1) == 2.0
        assert policy.wait_for(2) == 4.0
        assert policy.wait_for(3) == 8.0

    def test_max_wait_caps_growth(self):
        policy = RetryPolicy(retries=10, timeout=1.0, backoff=10.0, max_wait=5.0)
        assert policy.wait_for(0) == 1.0
        assert policy.wait_for(1) == 5.0
        # Cap holds for every higher attempt.
        assert policy.wait_for(5) == 5.0

    def test_jitter_stays_within_bounds(self):
        policy = RetryPolicy(retries=3, timeout=10.0, jitter=0.5)
        # 100 draws around the same attempt — none may escape ±50%.
        random.seed(0)
        for _ in range(100):
            w = policy.wait_for(0)
            assert 5.0 <= w <= 15.0

    def test_jitter_never_drops_below_zero(self):
        # If jitter > 1.0 the raw sample could push the wait negative;
        # the floor at 0 prevents the loop from spinning.
        policy = RetryPolicy(retries=1, timeout=1.0, jitter=2.0)
        random.seed(0)
        for _ in range(50):
            assert policy.wait_for(0) >= 0.0


class TestPolicyFromLegacy:
    def test_explicit_policy_wins(self):
        explicit = RetryPolicy(retries=7, timeout=42.0, backoff=2.0)
        resolved = policy_from_legacy(explicit, retries=1, timeout=1)
        assert resolved is explicit

    def test_legacy_args_build_flat_policy(self):
        resolved = policy_from_legacy(None, retries=2, timeout=3)
        assert resolved.retries == 2
        assert resolved.timeout == 3.0
        assert resolved.backoff == 1.0
        assert resolved.jitter == 0.0


class TestLegacyAttrMixin:
    """Verify the property proxies the sync/async clients rely on."""

    def test_setting_retries_rebuilds_policy(self):
        # Import here so the test doesn't initialise sockets.
        from pyrad2.client import Client

        client = Client(server="localhost", retries=3, timeout=5)
        assert client.retries == 3
        client.retries = 9
        assert client.retries == 9
        assert client.retry_policy.retries == 9
        # Other policy fields are preserved.
        assert client.retry_policy.timeout == 5.0

    def test_setting_timeout_rebuilds_policy(self):
        from pyrad2.client import Client

        client = Client(server="localhost", retries=3, timeout=5)
        client.timeout = 0
        assert client.timeout == 0.0
        assert client.retry_policy.timeout == 0.0


class TestRetryPolicyIntegration:
    """Smoke tests: a non-flat policy actually feeds the client loop."""

    def test_sync_client_uses_policy(self):
        from pyrad2.client import Client

        policy = RetryPolicy(
            retries=2, timeout=1.0, backoff=2.0, jitter=0.0, max_wait=10.0
        )
        client = Client(server="localhost", retry_policy=policy)
        assert client.retry_policy is policy
        assert client.retries == 2
        assert client.retry_policy.wait_for(0) == 1.0
        assert client.retry_policy.wait_for(1) == 2.0

    def test_async_client_uses_policy(self):
        from pyrad2.client_async import ClientAsync

        policy = RetryPolicy(retries=4, timeout=2.0, backoff=2.0, max_wait=20.0)
        client = ClientAsync(server="localhost", retry_policy=policy)
        assert client.retry_policy is policy
        assert client.retries == 4
        assert client.timeout == 2.0
