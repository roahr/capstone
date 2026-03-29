"""
Base LLM Client: Abstract interface for all LLM providers.

All provider clients (Gemini, Groq, etc.) implement this interface
so the consensus engine and agents are provider-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from src.sast.sarif.schema import Finding


class BaseLLMClient(ABC):
    """Abstract LLM client that all providers must implement."""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        use_pro: bool = False,
        json_mode: bool = True,
        system_instruction: str | None = None,
    ) -> dict[str, Any] | str:
        """Generate a response from the LLM."""
        ...

    @abstractmethod
    async def generate_batch(
        self,
        prompts: list[str],
        use_pro: bool = False,
        json_mode: bool = True,
        system_instruction: str | None = None,
    ) -> list[dict[str, Any] | str]:
        """Send multiple prompts with concurrency control."""
        ...

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the client is configured and has remaining quota."""
        ...

    @property
    @abstractmethod
    def remaining_quota(self) -> dict[str, int]:
        """Return remaining API quota."""
        ...

    @abstractmethod
    def get_usage_report(self) -> dict[str, Any]:
        """Return usage statistics."""
        ...

    @property
    def provider_name(self) -> str:
        """Human-readable provider name."""
        return self.__class__.__name__
