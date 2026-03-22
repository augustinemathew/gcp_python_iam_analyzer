"""Configure test imports for agent-sandbox."""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root and agent-sandbox to path
_project_root = Path(__file__).parent.parent.parent
_agent_sandbox = Path(__file__).parent.parent

sys.path.insert(0, str(_project_root))
sys.path.insert(0, str(_agent_sandbox))
