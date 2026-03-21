"""
PhishGuard AI - Cache Service
Dictionary-based LRU cache for instant repeated scan results.
"""
import hashlib
import time
import threading
import logging
from collections import OrderedDict

logger = logging.getLogger(__name__)


class ScanCache:
    """Thread-safe LRU cache for scan results."""

    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self._cache = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl  # seconds
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def _make_key(self, input_text: str, mode: str) -> str:
        """Create a cache key from input and mode."""
        content = f"{mode}:{input_text.strip().lower()}"
        return hashlib.sha256(content.encode()).hexdigest()

    def get(self, input_text: str, mode: str) -> dict | None:
        """Retrieve cached result."""
        key = self._make_key(input_text, mode)
        with self._lock:
            if key in self._cache:
                entry, timestamp = self._cache[key]
                if time.time() - timestamp < self._ttl:
                    # Move to end (most recently used)
                    self._cache.move_to_end(key)
                    self._hits += 1
                    result = dict(entry)
                    result['cached'] = True
                    return result
                else:
                    # Expired
                    del self._cache[key]
            self._misses += 1
            return None

    def set(self, input_text: str, mode: str, result: dict) -> None:
        """Store result in cache."""
        key = self._make_key(input_text, mode)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (result, time.time())
            # Evict oldest if over limit
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()

    def stats(self) -> dict:
        """Return cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0
            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(hit_rate, 2)
            }


# Global singleton cache instance
scan_cache = ScanCache(max_size=1000, ttl=3600)
