"""Taint tracking: labels, propagation, and process tracking.

Taint labels track information flow. The key invariant: taint is monotonic
(only increases, never decreases) and transitive (children inherit parent taint).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Flag, auto


class TaintLabel(Flag):
    """Taint labels indicating data sensitivity categories."""

    NONE = 0
    CREDENTIAL = auto()    # API keys, passwords, tokens
    PII = auto()           # Personal identifiable information
    FINANCIAL = auto()     # Financial data
    MEDICAL = auto()       # Medical/health data
    INFRASTRUCTURE = auto()  # Internal infrastructure details
    SOURCE_CODE = auto()   # Proprietary source code


@dataclass
class ProcessTaint:
    """Taint state for a single process."""

    pid: int
    label: TaintLabel = TaintLabel.NONE
    sources: list[str] = field(default_factory=list)
    parent_pid: int | None = None

    @property
    def is_tainted(self) -> bool:
        return self.label != TaintLabel.NONE

    def add_taint(self, label: TaintLabel, source: str) -> None:
        """Add a taint label. Taint is monotonic — only increases."""
        self.label |= label
        if source not in self.sources:
            self.sources.append(source)


@dataclass
class FileTaint:
    """Taint state for a file."""

    path: str
    label: TaintLabel = TaintLabel.NONE
    written_by: list[int] = field(default_factory=list)  # PIDs that wrote to this file

    @property
    def is_tainted(self) -> bool:
        return self.label != TaintLabel.NONE


class TaintTracker:
    """Tracks taint across processes and files.

    Properties:
    - Monotonic: taint only increases, never decreases
    - Transitive: children inherit parent taint
    - File propagation: reading a tainted file taints the process,
      writing from a tainted process taints the file
    """

    def __init__(self) -> None:
        self._processes: dict[int, ProcessTaint] = {}
        self._files: dict[str, FileTaint] = {}
        self._fd_to_path: dict[tuple[int, int], str] = {}  # (pid, fd) -> path

    def register_process(self, pid: int, parent_pid: int | None = None) -> ProcessTaint:
        """Register a new process, inheriting parent taint."""
        proc = ProcessTaint(pid=pid, parent_pid=parent_pid)
        if parent_pid and parent_pid in self._processes:
            parent = self._processes[parent_pid]
            proc.label = parent.label  # Inherit taint
            proc.sources = list(parent.sources)
        self._processes[pid] = proc
        return proc

    def get_process(self, pid: int) -> ProcessTaint | None:
        return self._processes.get(pid)

    def get_file(self, path: str) -> FileTaint | None:
        return self._files.get(path)

    def taint_process(self, pid: int, label: TaintLabel, source: str) -> None:
        """Taint a process with a label."""
        proc = self._processes.get(pid)
        if proc is None:
            proc = self.register_process(pid)
        proc.add_taint(label, source)

    def taint_file(self, path: str, label: TaintLabel) -> None:
        """Directly taint a file (e.g., from pre-scan classification)."""
        ft = self._files.get(path)
        if ft is None:
            ft = FileTaint(path=path)
            self._files[path] = ft
        ft.label |= label

    def on_open(self, pid: int, fd: int, path: str) -> None:
        """Record a file open and propagate taint from file to process."""
        self._fd_to_path[(pid, fd)] = path
        ft = self._files.get(path)
        if ft and ft.is_tainted:
            self.taint_process(pid, ft.label, path)

    def on_read(self, pid: int, fd: int) -> None:
        """Record a file read — taint propagates from file to process."""
        path = self._fd_to_path.get((pid, fd))
        if path:
            ft = self._files.get(path)
            if ft and ft.is_tainted:
                self.taint_process(pid, ft.label, path)

    def on_write(self, pid: int, fd: int) -> None:
        """Record a file write — taint propagates from process to file."""
        path = self._fd_to_path.get((pid, fd))
        if not path:
            return
        proc = self._processes.get(pid)
        if proc and proc.is_tainted:
            ft = self._files.get(path)
            if ft is None:
                ft = FileTaint(path=path)
                self._files[path] = ft
            ft.label |= proc.label
            if pid not in ft.written_by:
                ft.written_by.append(pid)

    def on_close(self, pid: int, fd: int) -> None:
        """Record a file close."""
        self._fd_to_path.pop((pid, fd), None)

    def on_fork(self, parent_pid: int, child_pid: int) -> ProcessTaint:
        """Record a fork — child inherits parent taint."""
        return self.register_process(child_pid, parent_pid)

    def is_process_tainted(self, pid: int) -> bool:
        proc = self._processes.get(pid)
        return proc.is_tainted if proc else False

    def get_process_taint(self, pid: int) -> TaintLabel:
        proc = self._processes.get(pid)
        return proc.label if proc else TaintLabel.NONE
