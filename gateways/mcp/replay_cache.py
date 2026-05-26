"""In-memory LRU cache that records seen ``jti`` claims to prevent token replay.

The MCP gateway tracks every PASETO ``jti`` it has accepted; a second
appearance of the same ``jti`` within the TTL window is rejected with HTTP
401 / ``deny_reason="token_replay"``.

This intentionally lives in memory only — replay protection is best-effort
across process restarts; the auth gateway's short TTL (≤300s) bounds the
exposure window.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

__all__ = ["ReplayCache"]


class ReplayCache:
    """Fixed-size, thread-safe LRU set of recently-seen ``jti`` values.

    ``seen(jti, exp_ts)`` returns ``True`` if the jti was already recorded
    within the current TTL window; otherwise it records the jti (evicting the
    least-recently-used entry if at capacity) and returns ``False``.

    Entries automatically expire when ``time.time() > exp_ts``; expired
    entries are skipped on lookup and pruned lazily on insert.
    """

    def __init__(self, *, capacity: int = 10_000) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        self._capacity = capacity
        # jti -> expiry epoch seconds; OrderedDict gives us LRU semantics.
        self._entries: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def capacity(self) -> int:
        return self._capacity

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def seen(self, jti: str, exp_ts: float) -> bool:
        """Return True iff ``jti`` was already recorded and is still valid."""
        if not jti:
            return False
        now = time.time()
        with self._lock:
            existing = self._entries.get(jti)
            if existing is not None:
                if existing > now:
                    # Touch to refresh LRU position.
                    self._entries.move_to_end(jti)
                    return True
                # Expired entry — drop and treat as unseen.
                del self._entries[jti]
            self._entries[jti] = exp_ts
            self._entries.move_to_end(jti)
            if len(self._entries) > self._capacity:
                self._entries.popitem(last=False)
            return False

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
