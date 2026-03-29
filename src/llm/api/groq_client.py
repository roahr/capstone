"""
Groq API Client: Fast LLM inference via Groq's LPU hardware.

Groq free tier (March 2026):
  - llama-3.3-70b-versatile: 30 RPM, 1000 RPD, 12K TPM
  - llama-3.1-8b-instant:    30 RPM, 14400 RPD, 6K TPM
  - qwen/qwen3-32b:          60 RPM, 1000 RPD, 6K TPM

Set via .env:
  LLM_PROVIDER=groq
  GROQ_API_KEY=gsk_...
  LLM_MODEL=llama-3.3-70b-versatile
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from typing import Any

from src.llm.api.base_client import BaseLLMClient

logger = logging.getLogger(__name__)

# Groq model catalog with free tier limits
GROQ_MODELS = {
    "llama-3.3-70b-versatile": {"rpm": 30, "rpd": 1000, "tpm": 12000},
    "llama-3.1-8b-instant": {"rpm": 30, "rpd": 14400, "tpm": 6000},
    "qwen/qwen3-32b": {"rpm": 60, "rpd": 1000, "tpm": 6000},
    "meta-llama/llama-4-scout-17b-16e-instruct": {"rpm": 30, "rpd": 1000, "tpm": 30000},
    "moonshotai/kimi-k2-instruct": {"rpm": 60, "rpd": 1000, "tpm": 10000},
}

DEFAULT_MODEL = "llama-3.3-70b-versatile"
DEFAULT_FAST_MODEL = "llama-3.1-8b-instant"


class _SimpleCache:
    """LRU prompt cache."""

    def __init__(self, max_size: int = 500):
        self._store: OrderedDict[str, Any] = OrderedDict()
        self._max_size = max_size
        self.hits = 0
        self.misses = 0

    def _key(self, prompt: str, model: str) -> str:
        h = hashlib.sha256(f"{prompt}:{model}".encode("utf-8", errors="replace"))
        return h.hexdigest()

    def get(self, prompt: str, model: str) -> Any | None:
        k = self._key(prompt, model)
        if k in self._store:
            self.hits += 1
            self._store.move_to_end(k)
            return self._store[k]
        self.misses += 1
        return None

    def put(self, prompt: str, model: str, value: Any) -> None:
        k = self._key(prompt, model)
        self._store[k] = value
        self._store.move_to_end(k)
        while len(self._store) > self._max_size:
            self._store.popitem(last=False)


class GroqClient(BaseLLMClient):
    """
    LLM client for Groq API.

    Uses httpx for async HTTP calls to Groq's OpenAI-compatible endpoint.
    Supports the same interface as GeminiClient for drop-in replacement.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

        # API keys -- supports multi-key rotation via GROQ_API_KEYS (comma-separated)
        self._keys: list[str] = []
        self._current_key_idx = 0
        self._per_key_requests: dict[int, int] = {}
        self._init_keys()

        # Backward-compatible single key property
        self.api_key = self._keys[0] if self._keys else None

        # Models
        self._model_pro = self.config.get("model_pro", DEFAULT_MODEL)
        self._model_flash = self.config.get("model_flash", DEFAULT_FAST_MODEL)

        # Override from env
        env_model = os.environ.get("LLM_MODEL")
        if env_model:
            self._model_pro = env_model
            self._model_flash = env_model
            logger.info("Model overridden from LLM_MODEL env: %s", env_model)

        # Generation config
        self.temperature = self.config.get("temperature", 0.1)
        self.max_output_tokens = self.config.get("max_output_tokens", 4096)
        self._max_retries = self.config.get("max_retries", 3)
        self._max_concurrent = self.config.get("max_concurrent", 5)
        self._semaphore: asyncio.Semaphore | None = None

        # Rate tracking
        self._total_requests = 0
        self._total_errors = 0
        self._total_cached = 0
        self._start_time = time.monotonic()

        # Cache
        self._cache = _SimpleCache(max_size=self.config.get("cache_size", 500))

        # API base
        self._api_base = "https://api.groq.com/openai/v1/chat/completions"

    def _init_keys(self) -> None:
        """Load API keys from environment. Supports multi-key via GROQ_API_KEYS."""
        # Multi-key (comma-separated)
        multi = os.environ.get("GROQ_API_KEYS", "")
        if multi:
            self._keys = [k.strip() for k in multi.split(",") if k.strip()]

        # Single-key fallback
        if not self._keys:
            single_env = self.config.get("api_key_env", "GROQ_API_KEY")
            single = os.environ.get(single_env, "")
            if single.strip():
                self._keys = [single.strip()]

        if not self._keys:
            logger.warning(
                "No Groq API key found in GROQ_API_KEYS or GROQ_API_KEY. "
                "LLM validation will be unavailable."
            )
            return

        for i in range(len(self._keys)):
            self._per_key_requests[i] = 0

        masked = [f"...{k[-4:]}" if len(k) > 4 else "***" for k in self._keys]
        logger.info("Groq client initialized with %d API key(s): %s", len(self._keys), ", ".join(masked))

    def _get_current_key(self) -> str | None:
        """Get the current API key."""
        if not self._keys:
            return None
        return self._keys[self._current_key_idx]

    def _rotate_key(self, reason: str = "") -> str | None:
        """Rotate to the next API key. Returns the new key or None."""
        if len(self._keys) <= 1:
            return self._get_current_key()
        old_idx = self._current_key_idx
        self._current_key_idx = (self._current_key_idx + 1) % len(self._keys)
        logger.info(
            "Groq key rotated from ...%s to ...%s (reason: %s)",
            self._keys[old_idx][-4:], self._keys[self._current_key_idx][-4:], reason or "rate-limit",
        )
        return self._keys[self._current_key_idx]

    @property
    def provider_name(self) -> str:
        return "Groq"

    @property
    def model_pro(self) -> str:
        return self._model_pro

    @property
    def model_flash(self) -> str:
        return self._model_flash

    async def generate(
        self,
        prompt: str,
        use_pro: bool = False,
        json_mode: bool = True,
        system_instruction: str | None = None,
    ) -> dict[str, Any] | str:
        """Generate via Groq's OpenAI-compatible API."""
        model = self._model_pro if use_pro else self._model_flash

        # Cache check
        cached = self._cache.get(prompt, model)
        if cached is not None:
            self._total_cached += 1
            return cached

        current_key = self._get_current_key()
        if not current_key:
            return {"error": True, "error_type": "NoAPIKey", "error_message": "GROQ_API_KEY not set"}

        # Build messages
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        # Build request body
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        # Retry loop with key rotation on 429
        import httpx

        for attempt in range(self._max_retries + 1):
            headers = {
                "Authorization": f"Bearer {current_key}",
                "Content-Type": "application/json",
            }

            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.post(
                        self._api_base,
                        json=body,
                        headers=headers,
                    )

                self._total_requests += 1
                self._per_key_requests[self._current_key_idx] = (
                    self._per_key_requests.get(self._current_key_idx, 0) + 1
                )

                if response.status_code == 429:
                    # Rate limited -- rotate key if available, then retry
                    if len(self._keys) > 1:
                        current_key = self._rotate_key("429-rate-limit")
                        logger.info("Retrying with rotated key after 429")
                        continue
                    retry_after = float(response.headers.get("retry-after", 2 ** attempt))
                    logger.warning("Groq rate limited, waiting %.1fs", retry_after)
                    await asyncio.sleep(retry_after)
                    continue

                if response.status_code != 200:
                    error_text = response.text[:200]
                    if attempt < self._max_retries:
                        logger.warning("Groq API error %d: %s, retrying", response.status_code, error_text)
                        await asyncio.sleep(2 ** attempt)
                        continue
                    self._total_errors += 1
                    return {"error": True, "error_type": f"HTTP_{response.status_code}", "error_message": error_text}

                # Parse response
                data = response.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")

                if not content:
                    return {} if json_mode else ""

                if json_mode:
                    result = self._parse_json(content, model)
                else:
                    result = content

                # Cache
                cache_val = result if isinstance(result, dict) else {"_raw": result}
                self._cache.put(prompt, model, cache_val)
                return result

            except Exception as e:
                if attempt < self._max_retries:
                    logger.warning("Groq request failed (attempt %d): %s", attempt + 1, e)
                    await asyncio.sleep(2 ** attempt)
                else:
                    self._total_errors += 1
                    logger.error("Groq API failed after %d attempts: %s", self._max_retries + 1, e)
                    return {"error": True, "error_type": type(e).__name__, "error_message": str(e)}

        return {"error": True, "error_type": "MaxRetries", "error_message": "All retries exhausted"}

    async def generate_batch(
        self,
        prompts: list[str],
        use_pro: bool = False,
        json_mode: bool = True,
        system_instruction: str | None = None,
    ) -> list[dict[str, Any] | str]:
        """Send multiple prompts with concurrency control."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrent)

        async def _bounded(prompt: str) -> dict[str, Any] | str:
            async with self._semaphore:
                try:
                    return await self.generate(prompt, use_pro, json_mode, system_instruction)
                except Exception as e:
                    return {"error": True, "error_type": type(e).__name__, "error_message": str(e)}

        return list(await asyncio.gather(*[_bounded(p) for p in prompts]))

    @property
    def is_available(self) -> bool:
        return len(self._keys) > 0

    @property
    def remaining_quota(self) -> dict[str, int]:
        model_info = GROQ_MODELS.get(self._model_pro, {"rpd": 1000})
        # Each key gets its own quota -- total = keys * per_key_rpd
        total_rpd = model_info["rpd"] * len(self._keys)
        used = self._total_requests
        remaining = max(total_rpd - used, 0)
        return {"pro_remaining": remaining, "flash_remaining": remaining}

    def get_usage_report(self) -> dict[str, Any]:
        uptime = time.monotonic() - self._start_time
        per_key = []
        for i, key in enumerate(self._keys):
            masked = f"...{key[-4:]}" if len(key) > 4 else "***"
            per_key.append({
                "key_id": masked,
                "requests": self._per_key_requests.get(i, 0),
            })
        return {
            "provider": "groq",
            "model_pro": self._model_pro,
            "model_flash": self._model_flash,
            "uptime_seconds": round(uptime, 1),
            "total_requests": self._total_requests,
            "total_cached_hits": self._total_cached,
            "total_errors": self._total_errors,
            "total_keys": len(self._keys),
            "active_key_idx": self._current_key_idx,
            "per_key": per_key,
            "cache": {
                "hits": self._cache.hits,
                "misses": self._cache.misses,
            },
        }

    @staticmethod
    def _parse_json(text: str, model: str) -> dict[str, Any]:
        """Parse JSON from response, handling markdown fences."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        stripped = text.strip()
        if stripped.startswith("```"):
            lines = stripped.split("\n")
            stripped = "\n".join(l for l in lines if not l.startswith("```")).strip()
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass
        logger.warning("Failed to parse JSON from %s (%s)", model, text[:100])
        return {"raw_response": text}
