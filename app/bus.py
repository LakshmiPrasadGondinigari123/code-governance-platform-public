"""In-process pub/sub used for the live (SSE) streams the UI subscribes to."""
import asyncio
import threading
import time

_subs = []  # (loop, queue, tenant, channel)
_lock = threading.Lock()


def subscribe(tenant: str, channel: str = "findings") -> asyncio.Queue:
    q = asyncio.Queue(maxsize=2000)
    with _lock:
        _subs.append((asyncio.get_running_loop(), q, tenant, channel))
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    with _lock:
        _subs[:] = [s for s in _subs if s[1] is not q]


def _put(q, event):
    try:
        q.put_nowait(event)
    except asyncio.QueueFull:
        pass


def publish(tenant: str, channel: str, event: dict) -> None:
    event = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **event}
    with _lock:
        targets = [s for s in _subs if s[2] == tenant and s[3] == channel]
    for loop, q, _, _ in targets:
        try:
            loop.call_soon_threadsafe(_put, q, event)
        except RuntimeError:
            pass
