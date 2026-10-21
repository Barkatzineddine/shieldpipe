import threading
import time
from collections import deque
from collections.abc import Callable

_MAX_TRACKED_KEYS = 10_000


class SlidingWindowLimiter:
    """In-memory sliding window counter.

    State lives in the process, so limits apply per replica. A shared store (Redis)
    is needed before scaling the API horizontally; see docs/threat-model.md.
    """

    def __init__(
        self,
        max_events: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_events = max_events
        self._window = window_seconds
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, events: deque[float], now: float) -> None:
        while events and now - events[0] >= self._window:
            events.popleft()

    def retry_after(self, key: str) -> float:
        """Seconds until the key may try again, or 0 if it is not limited."""
        now = self._clock()
        with self._lock:
            events = self._events.get(key)
            if not events:
                return 0.0
            self._prune(events, now)
            if len(events) < self._max_events:
                return 0.0
            return max(self._window - (now - events[0]), 0.0)

    def hit(self, key: str) -> None:
        now = self._clock()
        with self._lock:
            if key not in self._events and len(self._events) >= _MAX_TRACKED_KEYS:
                self._evict_stale(now)
            events = self._events.setdefault(key, deque())
            self._prune(events, now)
            events.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)

    def _evict_stale(self, now: float) -> None:
        for key in list(self._events):
            events = self._events[key]
            self._prune(events, now)
            if not events:
                del self._events[key]


class LoginThrottle:
    """Throttles failed logins per account and, more loosely, per source IP.

    The per-IP limit catches password spraying across many accounts.
    """

    def __init__(self, max_attempts: int, window_seconds: float) -> None:
        self.per_account = SlidingWindowLimiter(max_attempts, window_seconds)
        self.per_ip = SlidingWindowLimiter(max_attempts * 4, window_seconds)

    def retry_after(self, ip: str, username: str) -> float:
        return max(self.per_account.retry_after(username), self.per_ip.retry_after(ip))

    def record_failure(self, ip: str, username: str) -> None:
        self.per_account.hit(username)
        self.per_ip.hit(ip)

    def record_success(self, username: str) -> None:
        self.per_account.reset(username)
