"""JSONL request/response logging for LLM calls."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path


class LLMLogger:
    """Logs prompts and responses to JSONL for replay and auditing."""

    def __init__(self, log_dir: Path, prefix: str = "mapping"):
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        self._path = log_dir / f"{prefix}_{ts}.jsonl"
        self._f = open(self._path, "a")  # noqa: SIM115
        print(f"Logging to {self._path}", file=sys.stderr)

    def log(
        self,
        *,
        service_id: str,
        batch_idx: int,
        prompt: str,
        response: str,
        model: str,
    ) -> None:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "model": model,
            "service_id": service_id,
            "batch_idx": batch_idx,
            "prompt": prompt,
            "response": response,
        }
        self._f.write(json.dumps(entry) + "\n")
        self._f.flush()

    def close(self) -> None:
        self._f.close()
