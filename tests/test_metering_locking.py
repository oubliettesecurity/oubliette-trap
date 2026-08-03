"""Quota reads must hold the lock they are documented to require.

``_get_or_create_summary`` says "Caller must hold _lock or call within locked
context", and ``record`` obeys that. ``check_quota`` did not: it called the same
helper and then read the returned summary's counters with no lock held, so a
concurrent ``record`` could mutate the summaries mapping underneath it.

Tested by instrumenting the manager's own lock rather than by racing threads.
A thread race reproduces this only sometimes and would be a flaky test; the
invariant -- "the lock is held while shared metering state is touched" -- is
exact and can be asserted directly.
"""

from __future__ import annotations

import threading

import pytest

from oubliette_trap.metering import UsageTracker


class _TrackingLock:
    """RLock that records whether it is currently held."""

    def __init__(self) -> None:
        self._inner = threading.RLock()
        self.depth = 0
        #: How many times the lock has been fully released (depth back to 0).
        #: A single atomic operation should reach zero exactly once, at the end.
        self.releases_to_zero = 0

    def __enter__(self):
        self._inner.__enter__()
        self.depth += 1
        return self

    def __exit__(self, *exc):
        self.depth -= 1
        if self.depth == 0:
            self.releases_to_zero += 1
        return self._inner.__exit__(*exc)

    def acquire(self, *a, **kw):
        got = self._inner.acquire(*a, **kw)
        if got:
            self.depth += 1
        return got

    def release(self):
        self.depth -= 1
        if self.depth == 0:
            self.releases_to_zero += 1
        return self._inner.release()

    @property
    def held(self) -> bool:
        return self.depth > 0


@pytest.fixture
def meter():
    m = UsageTracker(tier="pro")
    m._lock = _TrackingLock()
    return m


def _assert_locked_during_summary_access(meter, call):
    """Run `call`, asserting the lock is held whenever shared state is read."""
    observed: list[bool] = []
    original = meter._get_or_create_summary

    def spy(month):
        observed.append(meter._lock.held)
        return original(month)

    meter._get_or_create_summary = spy
    call()
    assert observed, "shared metering state was never touched -- test proves nothing"
    assert all(observed), (
        "shared metering state was read without holding _lock, which "
        "_get_or_create_summary documents as required"
    )


def test_check_quota_holds_the_lock(meter):
    _assert_locked_during_summary_access(meter, lambda: meter.check_quota("api_call", 1))


def test_record_holds_the_lock(meter):
    """The path that already obeyed the contract -- pins it so it stays that way."""
    _assert_locked_during_summary_access(meter, lambda: meter.record("api_call", 1))


def test_record_checks_and_increments_without_ever_releasing_the_lock(meter):
    """The actual TOCTOU property, which "is the lock held?" does not capture.

    Once `check_quota` takes the lock itself, a `record` that calls it *before*
    acquiring still looks locked at every observation point -- yet the lock
    drops to zero in between, which is exactly the window where a second caller
    slips an increment past a check only one of them should have passed.

    So assert the stronger thing: one `record` releases the lock to depth zero
    exactly once, at the end. Two releases means check and increment happened
    in separate critical sections.
    """
    meter._lock.releases_to_zero = 0
    meter.record("api_call", 1)
    assert meter._lock.releases_to_zero == 1, (
        f"record() released the lock {meter._lock.releases_to_zero} times; the "
        f"quota check and the counter update must share one critical section"
    )


def test_check_quota_still_rejects_negative_quantity(meter):
    """The existing input-validation contract must survive the locking change."""
    with pytest.raises(ValueError):
        meter.check_quota("api_call", -1)


def test_check_quota_still_returns_true_within_quota(meter):
    assert meter.check_quota("api_call", 1) is True


def test_concurrent_checks_and_records_do_not_corrupt_counters():
    """End-to-end sanity: parallel traffic must not lose or duplicate usage."""
    meter = UsageTracker(tier="enterprise")
    errors: list[Exception] = []

    def worker():
        try:
            for _ in range(50):
                meter.check_quota("api_call", 1)
                meter.record("api_call", 1)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent metering raised: {errors[:3]}"
    summary = meter._get_or_create_summary(meter._month_key())
    assert summary.api_calls == 8 * 50
