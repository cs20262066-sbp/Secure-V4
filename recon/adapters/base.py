"""
Tool adapter interface for Secure recon engine.
All external tools go through adapters — never shell=True with user input.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    tool: str
    success: bool
    items: List[Any] = field(default_factory=list)
    raw: str = ""
    error: Optional[str] = None
    exit_code: Optional[int] = None
    meta: Dict[str, Any] = field(default_factory=dict)


class ToolAdapter(ABC):
    name: str = "base"
    binary_names: List[str] = []  # candidate executables on PATH

    def is_available(self) -> bool:
        for b in self.binary_names:
            if shutil.which(b):
                return True
        return False

    def resolve_binary(self) -> Optional[str]:
        for b in self.binary_names:
            path = shutil.which(b)
            if path:
                return path
        return None

    @abstractmethod
    def build_command(self, target: str, **kwargs) -> List[str]:
        ...

    def execute(
        self,
        target: str,
        timeout: int = 300,
        cwd: Optional[Path] = None,
        **kwargs,
    ) -> ToolResult:
        if not self.is_available():
            return ToolResult(
                tool=self.name,
                success=False,
                error=f"{self.name} is not installed",
            )
        cmd = self.build_command(target, **kwargs)
        # Hard rule: never shell=True
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(cwd) if cwd else None,
                shell=False,
            )
            raw = (proc.stdout or "") + (proc.stderr or "")
            items = self.parse(proc.stdout or "")
            items = self.normalize(items)
            return ToolResult(
                tool=self.name,
                success=proc.returncode == 0 or bool(items),
                items=items,
                raw=raw[:500_000],  # cap storage
                exit_code=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(tool=self.name, success=False, error="timeout")
        except Exception as e:
            logger.exception("%s execute failed", self.name)
            return ToolResult(tool=self.name, success=False, error=str(e)[:500])

    @abstractmethod
    def parse(self, stdout: str) -> List[Any]:
        ...

    def normalize(self, items: List[Any]) -> List[Any]:
        return items

    def installation_hint(self) -> str:
        return f"Install {self.name}. See Tool Center documentation."
