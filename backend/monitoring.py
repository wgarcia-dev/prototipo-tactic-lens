"""Short process-local snapshot cache; authorization stays on the route."""
from threading import Lock
from time import monotonic


class SnapshotCache:
    def __init__(self, ttl=0.75, clock=monotonic):
        self.ttl, self.clock = ttl, clock
        self.lock = Lock()
        self.key = self.value = None
        self.expires = 0

    def get(self, key, load):
        # Concurrent dashboard tabs share one computation, never a stale result
        # from another engine/test transaction. Failures are not cached.
        with self.lock:
            if self.key == key and self.expires > self.clock():
                return self.value
            value = load()
            self.key, self.value = key, value
            self.expires = self.clock() + self.ttl
            return value

    def invalidate(self):
        with self.lock:
            self.expires = 0
