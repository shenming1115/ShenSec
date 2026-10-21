"""Shared per-origin pacing, cancellable waits, and bounded safe retries."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from threading import Event, Lock
import time

from pydantic import BaseModel, ConfigDict, Field


class NetworkPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requests_per_second: float = Field(default=0, ge=0, le=100, allow_inf_nan=False)
    retries: int = Field(default=1, ge=0, le=3)
    backoff: float = Field(default=0.5, ge=0, le=10, allow_inf_nan=False)
    max_retry_after: float = Field(default=10, ge=0, le=60, allow_inf_nan=False)


class RequestPacer:
    def __init__(self, policy: NetworkPolicy):
        self.policy = policy
        self._lock = Lock()
        self._next: dict[str, float] = {}

    def wait(self, scope: str, event: Event) -> bool:
        rate = self.policy.requests_per_second
        if not rate:
            return not event.is_set()
        while not event.is_set():
            # Admit against actual time to avoid catch-up bursts after a stalled worker.
            with self._lock:
                now = time.monotonic()
                delay = self._next.get(scope, now) - now
                if delay <= 0:
                    self._next[scope] = now + 1 / rate
                    return True
            if event.wait(delay):
                return False
        return False


def retry_delay(value: str | None, attempt: int, policy: NetworkPolicy) -> float:
    delay = policy.backoff * 2 ** attempt
    if value:
        try:
            delay = max(delay, float(value))
        except ValueError:
            try:
                when = parsedate_to_datetime(value)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                delay = max(delay, (when - datetime.now(timezone.utc)).total_seconds())
            except (ValueError, TypeError, OverflowError):
                pass
    return min(max(0, delay), policy.max_retry_after)
