"""Pipeline infrastructure: Stage base class and PipelineContext."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Artifact:
    """A typed file produced or consumed by a stage."""

    path: Path
    description: str


@dataclass
class PipelineContext:
    """Shared state passed to every stage."""

    project_root: Path
    data_dir: Path
    force: bool = False
    services: list[str] | None = None
    dry_run: bool = False

    @classmethod
    def default(cls) -> PipelineContext:
        root = Path(__file__).parent.parent
        return cls(project_root=root, data_dir=root / "data")


class Stage(ABC):
    """Base class for pipeline stages."""

    name: str
    inputs: list[Artifact]
    outputs: list[Artifact]

    @abstractmethod
    def run(self, ctx: PipelineContext) -> None: ...

    def up_to_date(self) -> bool:
        """Check if all outputs are newer than all inputs."""
        input_times = []
        for a in self.inputs:
            if not a.path.exists():
                return False
            input_times.append(a.path.stat().st_mtime)

        output_times = []
        for a in self.outputs:
            if not a.path.exists():
                return False
            output_times.append(a.path.stat().st_mtime)

        if not input_times or not output_times:
            return False

        return min(output_times) > max(input_times)
