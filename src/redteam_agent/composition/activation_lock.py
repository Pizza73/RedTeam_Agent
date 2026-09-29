"""Host activation lock (SystemDesign §35.2).

One shared advisory file lock covers both normal startup and an explicit stopped-worker
migration/restore. A second production root that cannot acquire the lock refuses to
start (it does not force-steal the lock). The lock is held for the life of the root.
"""

from __future__ import annotations

import fcntl
from pathlib import Path
from types import TracebackType
from typing import IO

from redteam_agent.errors import ActivationLockError


class HostActivationLock:
    def __init__(self, lock_path: str) -> None:
        self._path = Path(lock_path)
        self._handle: IO[str] | None = None

    def acquire(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self._path, "w")  # noqa: SIM115 - held open for the lock lifetime
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise ActivationLockError("host activation lock is held by another root") from exc
        self._handle = handle

    def release(self) -> None:
        if self._handle is not None:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            self._handle.close()
            self._handle = None

    @property
    def held(self) -> bool:
        return self._handle is not None

    def __enter__(self) -> HostActivationLock:
        self.acquire()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.release()
