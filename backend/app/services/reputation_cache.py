import time
import asyncio
from typing import Any, Optional


class ReputationCache:
    """Simple async-safe in-memory TTL cache.

    Stores arbitrary values with an expiry timestamp. Use `get`/`set` from
    async code; the implementation is protected by an `asyncio.Lock` so it
    is safe to share across async tasks.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        now = time.time()
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            value, expires_at = item
            if expires_at <= now:
                # expired
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        expires_at = time.time() + float(ttl_seconds)
        async with self._lock:
            self._store[key] = (value, expires_at)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()


# Module-level cache instance convenient for import elsewhere
cache = ReputationCache()
