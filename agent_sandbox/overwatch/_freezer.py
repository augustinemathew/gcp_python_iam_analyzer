"""Container process freeze/unfreeze for Overwatch DEFER decisions."""

from __future__ import annotations

import os
import signal
import subprocess


class Freezer:
    """Freezes and unfreezes container processes.

    Uses `docker pause` for container mode (sends SIGSTOP to all PIDs
    atomically) or direct `os.kill` for subprocess mode.
    """

    def __init__(
        self,
        container_id: str | None = None,
        pid: int | None = None,
        timeout: float = 300.0,
    ) -> None:
        self._container_id = container_id
        self._pid = pid
        self._frozen = False
        self.timeout = timeout

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> None:
        """Pause all container processes."""
        if self._frozen:
            return
        if self._container_id:
            subprocess.run(
                ["docker", "pause", self._container_id],
                check=True,
                capture_output=True,
            )
        elif self._pid:
            os.kill(self._pid, signal.SIGSTOP)
        self._frozen = True

    def unfreeze(self) -> None:
        """Resume all container processes."""
        if not self._frozen:
            return
        if self._container_id:
            subprocess.run(
                ["docker", "unpause", self._container_id],
                check=True,
                capture_output=True,
            )
        elif self._pid:
            os.kill(self._pid, signal.SIGCONT)
        self._frozen = False
