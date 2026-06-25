from cachetools import TTLCache

class LRUCache:
    """带过期时间的 LRU 缓存。"""

    def __init__(self, maxsize: int = 10000, ttl: int = 300):
        self._cache = TTLCache(maxsize=maxsize, ttl=ttl)

    def get(self, key: str):
        return self._cache.get(key)

    def set(self, key: str, value):
        self._cache[key] = value

    def clear(self):
        self._cache.clear()
