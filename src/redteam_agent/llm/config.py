"""Local LLM configuration (SystemDesign §7).

The configuration pins ``provider=vllm`` and ``wire_api=chat_completions``. A
``base_url`` of ``None`` means no real local endpoint is configured for this host;
the qualification gate then reports ``NOT_RUN`` rather than fabricating a pass.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.models.base import StrictImmutableBoundaryModel


class LocalLLMEndpointConfig(StrictImmutableBoundaryModel):
    """Connection settings for a local vLLM OpenAI-compatible endpoint."""

    provider: Literal["vllm"] = "vllm"
    wire_api: Literal["chat_completions"] = "chat_completions"
    base_url: str | None = None
    model: str = Field(min_length=1)
    temperature: float = Field(ge=0.0, le=2.0, default=0.1)
    request_timeout_seconds: int = Field(gt=0, default=60)

    @model_validator(mode="after")
    def _bounded(self) -> LocalLLMEndpointConfig:
        # vLLM should bind to localhost / a managed closed interface (SystemDesign §38).
        if self.base_url is not None and not (
            self.base_url.startswith("http://") or self.base_url.startswith("https://")
        ):
            raise ValueError("base_url must be an http(s) URL")
        return self

    @property
    def endpoint_available(self) -> bool:
        return self.base_url is not None


__all__ = ["LocalLLMEndpointConfig"]
