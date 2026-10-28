"""Background jobs with cancellation and streamed events."""

from __future__ import annotations

import threading
import uuid
from typing import Any, Callable

from xray_forge.core.log import get_logger

log = get_logger(__name__)

Emit = Callable[[dict], None]


class JobContext:
    """Handed to a job function: report progress/items, check for cancel."""

    def __init__(self, job_id: str, emit: Emit, stop: threading.Event):
        self.id, self._emit, self.stop = job_id, emit, stop

    def progress(self, done: int, total: int) -> None:
        self._emit({"job": self.id, "type": "progress", "done": done, "total": total})

    def item(self, data: Any) -> None:
        self._emit({"job": self.id, "type": "item", "data": data})


class JobManager:
    def __init__(self, emit: Emit):
        self._emit = emit
        self._jobs: dict[str, tuple[threading.Thread, threading.Event]] = {}
        self._lock = threading.Lock()

    def start(self, kind: str, fn: Callable[[JobContext], Any]) -> str:
        job_id = uuid.uuid4().hex[:12]
        stop = threading.Event()
        ctx = JobContext(job_id, self._emit, stop)

        def run() -> None:
            self._emit({"job": job_id, "type": "started", "kind": kind})
            try:
                result = fn(ctx)
                self._emit({"job": job_id, "type": "done", "cancelled": stop.is_set(),
                            "result": result})
            except Exception as e:
                log.exception("job %s (%s) failed", job_id, kind)
                self._emit({"job": job_id, "type": "error",
                            "message": f"{type(e).__name__}: {e}"})
            finally:
                with self._lock:
                    self._jobs.pop(job_id, None)

        t = threading.Thread(target=run, name=f"job-{kind}-{job_id}", daemon=True)
        with self._lock:
            self._jobs[job_id] = (t, stop)
        t.start()
        return job_id

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            entry = self._jobs.get(job_id)
        if not entry:
            return False
        entry[1].set()
        return True

    def active(self) -> list[str]:
        with self._lock:
            return list(self._jobs)

    def cancel_all(self) -> None:
        with self._lock:
            for _t, stop in self._jobs.values():
                stop.set()

    def join(self, timeout: float = 5.0) -> None:
        with self._lock:
            threads = [t for t, _ in self._jobs.values()]
        for t in threads:
            t.join(timeout)
