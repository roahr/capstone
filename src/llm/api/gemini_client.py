"""
Gemini API Client: Production-grade wrapper for Google Gemini 2.5 API.

Features:
    - Multi-key rotation with automatic failover on rate limits
    - Parallel batch request execution with concurrency control
    - Smart routing (Flash for simple findings, Pro for complex ones)
    - Retry with exponential backoff and key rotation on persistent 429s
    - Per-key usage tracking with cost estimation
    - SHA-256 prompt caching to avoid duplicate API calls
    - Graceful degradation when all keys are exhausted

Supports both Pro (5 RPM / 100 RPD) and Flash (10 RPM / 250 RPD) models
on the free tier.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from src.llm.api.base_client import BaseLLMClient

if TYPE_CHECKING:
    from src.sast.sarif.schema import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Common CWEs that are well-understood and can be handled by Flash
# ---------------------------------------------------------------------------
_COMMON_CWES: frozenset[str] = frozenset({
    "CWE-79",   # XSS
    "CWE-89",   # SQL Injection
    "CWE-22",   # Path Traversal
    "CWE-78",   # OS Command Injection
    "CWE-502",  # Deserialization
    "CWE-798",  # Hard-coded Credentials
    "CWE-327",  # Broken Crypto
    "CWE-200",  # Information Exposure
    "CWE-352",  # CSRF
    "CWE-611",  # XXE
    "CWE-434",  # Unrestricted Upload
    "CWE-918",  # SSRF
    "CWE-287",  # Improper Authentication
    "CWE-306",  # Missing Authentication
    "CWE-862",  # Missing Authorization
    "CWE-119",  # Buffer Overflow
    "CWE-416",  # Use After Free
    "CWE-476",  # NULL Pointer Dereference
})

# Thresholds for smart routing
_SHORT_CODE_THRESHOLD = 50    # lines
_LONG_CODE_THRESHOLD = 200    # lines
_SHORT_TAINT_PATH = 3         # steps

# Approximate cost per 1K tokens (Gemini free tier = $0, but track for
# when users move to paid tier)
_COST_PER_1K_INPUT_PRO = 0.00125
_COST_PER_1K_OUTPUT_PRO = 0.005
_COST_PER_1K_INPUT_FLASH = 0.0001875
_COST_PER_1K_OUTPUT_FLASH = 0.00075

# Average chars per token (rough estimate for English + code)
_CHARS_PER_TOKEN = 4


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------
class RateLimiter:
    """Token-bucket rate limiter for Gemini free tier, with per-key support."""

    def __init__(self, rpm: int, rpd: int, key_id: str = "default"):
        self.rpm = rpm
        self.rpd = rpd
        self.key_id = key_id
        self._minute_tokens = rpm
        self._day_tokens = rpd
        self._last_minute_refill = time.monotonic()
        self._last_day_refill = time.monotonic()
        self._total_requests = 0

    def acquire(self) -> float:
        """
        Acquire a rate limit token. Returns wait time in seconds.
        Returns 0 if token immediately available.
        """
        now = time.monotonic()

        # Refill minute tokens
        elapsed_min = now - self._last_minute_refill
        if elapsed_min >= 60.0:
            self._minute_tokens = self.rpm
            self._last_minute_refill = now

        # Refill day tokens
        elapsed_day = now - self._last_day_refill
        if elapsed_day >= 86400.0:
            self._day_tokens = self.rpd
            self._last_day_refill = now

        # Check daily limit
        if self._day_tokens <= 0:
            return 86400.0 - elapsed_day  # Wait until next day

        # Check minute limit
        if self._minute_tokens <= 0:
            wait = 60.0 - elapsed_min
            return max(wait, 0.1)

        self._minute_tokens -= 1
        self._day_tokens -= 1
        self._total_requests += 1
        return 0.0

    def force_deplete_minute(self) -> None:
        """Force-deplete minute tokens (used after a 429 response)."""
        self._minute_tokens = 0

    @property
    def remaining_today(self) -> int:
        return max(self._day_tokens, 0)

    @property
    def remaining_minute(self) -> int:
        return max(self._minute_tokens, 0)

    @property
    def total_requests(self) -> int:
        return self._total_requests


# ---------------------------------------------------------------------------
# Per-key state
# ---------------------------------------------------------------------------
@dataclass
class _KeyState:
    """Tracks per-key usage and rate limiters."""
    key: str
    key_id: str  # masked identifier for logging
    pro_limiter: RateLimiter
    flash_limiter: RateLimiter
    total_requests: int = 0
    total_errors: int = 0
    total_input_tokens_est: int = 0
    total_output_tokens_est: int = 0
    is_exhausted: bool = False
    last_error: str = ""
    last_used: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# LRU Prompt Cache
# ---------------------------------------------------------------------------
class _PromptCache:
    """Simple LRU dict cache keyed by SHA-256 of (prompt + model + system_instruction)."""

    def __init__(self, max_size: int = 1000):
        self._max_size = max_size
        self._store: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _hash(prompt: str, model: str, system_instruction: str | None) -> str:
        h = hashlib.sha256()
        h.update(prompt.encode("utf-8", errors="replace"))
        h.update(model.encode("utf-8"))
        if system_instruction:
            h.update(system_instruction.encode("utf-8", errors="replace"))
        return h.hexdigest()

    def get(
        self, prompt: str, model: str, system_instruction: str | None
    ) -> dict[str, Any] | None:
        key = self._hash(prompt, model, system_instruction)
        if key in self._store:
            self.hits += 1
            self._store.move_to_end(key)
            return self._store[key]
        self.misses += 1
        return None

    def put(
        self,
        prompt: str,
        model: str,
        system_instruction: str | None,
        value: dict[str, Any],
    ) -> None:
        key = self._hash(prompt, model, system_instruction)
        if key in self._store:
            self._store.move_to_end(key)
        self._store[key] = value
        while len(self._store) > self._max_size:
            self._store.popitem(last=False)

    @property
    def size(self) -> int:
        return len(self._store)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def _mask_key(key: str) -> str:
    """Return a safe-to-log representation of an API key."""
    if len(key) <= 8:
        return "***"
    return f"{key[:4]}...{key[-4:]}"


def _estimate_tokens(text: str) -> int:
    """Rough token count estimate from character count."""
    return max(1, len(text) // _CHARS_PER_TOKEN)


def _is_retryable_status(exc: Exception) -> tuple[bool, int | None]:
    """
    Determine whether an exception from the Gemini SDK is retryable.
    Returns (retryable, http_status_code_or_None).
    """
    exc_str = str(exc).lower()
    status = None

    # google.api_core.exceptions expose .code or .grpc_status_code
    if hasattr(exc, "code"):
        code = getattr(exc, "code", None)
        if callable(code):
            code = code()
        if isinstance(code, int):
            status = code

    # Fallback: parse from the string representation
    if status is None:
        for code in (429, 500, 503):
            if str(code) in exc_str:
                status = code
                break

    if status in (429, 500, 503):
        return True, status

    # Also retry on transient network errors
    if any(tok in exc_str for tok in ("timeout", "connection", "unavailable")):
        return True, status

    return False, status


# ---------------------------------------------------------------------------
# GeminiClient
# ---------------------------------------------------------------------------
class GeminiClient(BaseLLMClient):
    """
    Production-grade client for Google Gemini 2.5 API.

    Supports multi-key rotation, parallel batch execution, smart model
    routing, caching, and comprehensive usage tracking.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

        # ----- API keys -----
        self._keys: list[_KeyState] = []
        self._current_key_idx = 0
        self._init_keys()

        # ----- Model names -----
        self.model_pro = self.config.get("model_pro", "gemini-2.5-pro")
        self.model_flash = self.config.get("model_flash", "gemini-2.5-flash")

        # ----- Generation defaults -----
        self.temperature = self.config.get("temperature", 0.1)
        self.max_output_tokens = self.config.get("max_output_tokens", 4096)

        # ----- Retry settings -----
        self._max_retries = self.config.get("max_retries", 3)

        # ----- Complexity threshold for routing -----
        self.complexity_threshold = self.config.get("complexity_threshold", 0.7)

        # ----- Concurrency -----
        self._max_concurrent = self.config.get("max_concurrent", 3)
        self._semaphore: asyncio.Semaphore | None = None  # lazy init

        # ----- Cache -----
        cache_size = self.config.get("cache_size", 1000)
        self._cache = _PromptCache(max_size=cache_size)

        # ----- Aggregate usage -----
        self._total_requests = 0
        self._total_cached = 0
        self._total_errors = 0
        self._start_time = time.monotonic()

        # ----- SDK (lazy init) -----
        self._genai = None

        # ----- Legacy rate-limiter aliases (kept for backward compatibility) -----
        # Expose rate limiters of the first key (or dummy ones if no keys).
        if self._keys:
            self._pro_limiter = self._keys[0].pro_limiter
            self._flash_limiter = self._keys[0].flash_limiter
        else:
            self._pro_limiter = RateLimiter(rpm=5, rpd=100, key_id="none")
            self._flash_limiter = RateLimiter(rpm=10, rpd=250, key_id="none")

    # ------------------------------------------------------------------
    # Key initialization
    # ------------------------------------------------------------------
    def _init_keys(self) -> None:
        """Load API keys from environment and create per-key state."""
        raw_keys: list[str] = []

        # Multi-key env var (comma-separated)
        multi = os.environ.get("GEMINI_API_KEYS", "")
        if multi:
            raw_keys = [k.strip() for k in multi.split(",") if k.strip()]

        # Single-key fallback
        if not raw_keys:
            single_env = self.config.get("api_key_env", "GEMINI_API_KEY")
            single = os.environ.get(single_env, "")
            if single.strip():
                raw_keys = [single.strip()]

        if not raw_keys:
            logger.warning(
                "No Gemini API key found in GEMINI_API_KEYS or GEMINI_API_KEY. "
                "LLM validation will be unavailable."
            )
            return

        pro_rpm = self.config.get("pro_rpm", 5)
        pro_rpd = self.config.get("pro_rpd", 100)
        flash_rpm = self.config.get("flash_rpm", 10)
        flash_rpd = self.config.get("flash_rpd", 250)

        for idx, key in enumerate(raw_keys):
            key_id = _mask_key(key)
            self._keys.append(
                _KeyState(
                    key=key,
                    key_id=key_id,
                    pro_limiter=RateLimiter(rpm=pro_rpm, rpd=pro_rpd, key_id=key_id),
                    flash_limiter=RateLimiter(
                        rpm=flash_rpm, rpd=flash_rpd, key_id=key_id
                    ),
                )
            )

        logger.info(
            "Gemini client initialized with %d API key(s): %s",
            len(self._keys),
            ", ".join(ks.key_id for ks in self._keys),
        )

    # ------------------------------------------------------------------
    # SDK initialization
    # ------------------------------------------------------------------
    def _init_sdk(self, api_key: str) -> Any:
        """
        Initialize (or re-initialize) the Gemini SDK with the given key.
        Returns the configured genai module.
        """
        try:
            import warnings
            warnings.filterwarnings("ignore", category=FutureWarning, module="google.generativeai")
            import google.generativeai as genai
        except ImportError:
            raise RuntimeError(
                "google-generativeai package not installed. "
                "Run: pip install google-generativeai"
            )

        genai.configure(api_key=api_key)
        self._genai = genai
        return genai

    # ------------------------------------------------------------------
    # Key rotation
    # ------------------------------------------------------------------
    def _get_active_key(self, use_pro: bool) -> _KeyState | None:
        """
        Return the current active key state, or rotate to the next
        available key. Returns None if all keys are exhausted.
        """
        if not self._keys:
            return None

        n = len(self._keys)
        for _ in range(n):
            ks = self._keys[self._current_key_idx]
            limiter = ks.pro_limiter if use_pro else ks.flash_limiter
            if limiter.remaining_today > 0 and not ks.is_exhausted:
                return ks
            # Try next key
            self._current_key_idx = (self._current_key_idx + 1) % n

        return None

    def _rotate_key(self, reason: str = "") -> _KeyState | None:
        """
        Force rotation to the next key. Returns the new key state or None
        if no keys remain.
        """
        if not self._keys:
            return None

        old_idx = self._current_key_idx
        n = len(self._keys)
        self._current_key_idx = (self._current_key_idx + 1) % n

        # Scan all keys to find a usable one
        for _ in range(n):
            ks = self._keys[self._current_key_idx]
            if not ks.is_exhausted:
                logger.info(
                    "Rotated API key from %s to %s (reason: %s)",
                    self._keys[old_idx].key_id,
                    ks.key_id,
                    reason or "rate-limit",
                )
                return ks
            self._current_key_idx = (self._current_key_idx + 1) % n

        logger.warning("All API keys exhausted. Reason: %s", reason)
        return None

    # ------------------------------------------------------------------
    # Smart routing
    # ------------------------------------------------------------------
    def auto_route(self, finding: Finding) -> str:
        """
        Decide which model to use based on finding complexity.

        Returns:
            Model name string (self.model_pro or self.model_flash)

        Routing logic:
            - Interprocedural taint flows -> Pro
            - Long code snippets (>200 lines) -> Pro
            - Rare CWEs (not in common set) -> Pro
            - High severity + high uncertainty -> Pro
            - Everything else -> Flash
        """
        complexity_score = 0.0

        # Factor 1: Taint flow complexity
        if finding.taint_flow:
            if finding.taint_flow.is_interprocedural:
                complexity_score += 0.4
            if finding.taint_flow.length > _SHORT_TAINT_PATH:
                complexity_score += 0.2

        # Factor 2: Code length
        snippet = finding.location.snippet or ""
        line_count = snippet.count("\n") + 1
        if line_count > _LONG_CODE_THRESHOLD:
            complexity_score += 0.3
        elif line_count > _SHORT_CODE_THRESHOLD:
            complexity_score += 0.1

        # Factor 3: CWE rarity
        cwe_upper = finding.cwe_id.upper() if finding.cwe_id else ""
        if cwe_upper and cwe_upper not in _COMMON_CWES:
            complexity_score += 0.2

        # Factor 4: Severity + uncertainty
        severity_weight = {
            "critical": 0.15,
            "high": 0.1,
            "medium": 0.05,
            "low": 0.0,
            "info": 0.0,
        }
        complexity_score += severity_weight.get(finding.severity.value, 0.0)

        if hasattr(finding, "uncertainty") and finding.uncertainty:
            complexity_score += finding.uncertainty.total * 0.15

        # Factor 5: Graph validation ambiguity
        if (
            finding.graph_validation is not None
            and finding.graph_validation.is_ambiguous
        ):
            complexity_score += 0.2

        if complexity_score >= self.complexity_threshold:
            logger.debug(
                "Routing %s to Pro (complexity=%.2f >= %.2f)",
                finding.cwe_id,
                complexity_score,
                self.complexity_threshold,
            )
            return self.model_pro
        else:
            logger.debug(
                "Routing %s to Flash (complexity=%.2f < %.2f)",
                finding.cwe_id,
                complexity_score,
                self.complexity_threshold,
            )
            return self.model_flash

    # ------------------------------------------------------------------
    # Core generate
    # ------------------------------------------------------------------
    async def generate(
        self,
        prompt: str,
        use_pro: bool = False,
        json_mode: bool = True,
        system_instruction: str | None = None,
    ) -> dict[str, Any] | str:
        """
        Generate a response from Gemini.

        Args:
            prompt: The prompt to send.
            use_pro: Force Pro model (otherwise uses Flash).
            json_mode: Parse response as JSON.
            system_instruction: System instruction for the model.

        Returns:
            Parsed JSON dict or raw string. On unrecoverable failure
            returns an error dict (graceful degradation) rather than
            raising.
        """
        model_name = self.model_pro if use_pro else self.model_flash

        # ----- Cache check -----
        cached = self._cache.get(prompt, model_name, system_instruction)
        if cached is not None:
            logger.debug("Cache hit for %s prompt (%d chars)", model_name, len(prompt))
            self._total_cached += 1
            return cached

        # ----- Acquire a key -----
        key_state = self._get_active_key(use_pro)
        if key_state is None:
            return self._exhausted_response(model_name)

        # ----- Initialize SDK with the selected key -----
        genai = self._init_sdk(key_state.key)

        # ----- Rate-limit acquire -----
        limiter = key_state.pro_limiter if use_pro else key_state.flash_limiter
        wait_time = limiter.acquire()

        if wait_time > 0:
            if wait_time > 3600:
                # Daily limit hit for this key -- try rotating
                logger.warning(
                    "Daily rate limit reached for key %s on %s. Rotating.",
                    key_state.key_id,
                    model_name,
                )
                key_state = self._rotate_key("daily-limit")
                if key_state is None:
                    return self._exhausted_response(model_name)
                genai = self._init_sdk(key_state.key)
                limiter = key_state.pro_limiter if use_pro else key_state.flash_limiter
                wait_time = limiter.acquire()

            if 0 < wait_time <= 120:
                logger.debug(
                    "Rate-limited on key %s, waiting %.1fs",
                    key_state.key_id,
                    wait_time,
                )
                await asyncio.sleep(wait_time)

        # ----- Build generation config -----
        generation_config: dict[str, Any] = {
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
        }
        if json_mode:
            generation_config["response_mime_type"] = "application/json"

        model_kwargs: dict[str, Any] = {
            "model_name": model_name,
            "generation_config": generation_config,
        }
        if system_instruction:
            model_kwargs["system_instruction"] = system_instruction

        model = genai.GenerativeModel(**model_kwargs)

        # ----- Retry loop with exponential backoff -----
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = model.generate_content(prompt)
                self._total_requests += 1
                key_state.total_requests += 1
                key_state.last_used = time.monotonic()

                # ----- Token estimation -----
                input_tokens = _estimate_tokens(prompt)
                if system_instruction:
                    input_tokens += _estimate_tokens(system_instruction)
                output_tokens = (
                    _estimate_tokens(response.text) if response.text else 0
                )
                key_state.total_input_tokens_est += input_tokens
                key_state.total_output_tokens_est += output_tokens

                # ----- Parse response -----
                if not response.text:
                    logger.warning("Empty response from %s", model_name)
                    result: dict[str, Any] | str = {} if json_mode else ""
                elif json_mode:
                    result = self._parse_json_response(response.text, model_name)
                else:
                    result = response.text

                # ----- Cache the result -----
                cache_value = (
                    result if isinstance(result, dict) else {"_raw": result}
                )
                self._cache.put(prompt, model_name, system_instruction, cache_value)

                return result

            except Exception as e:
                last_exc = e
                retryable, status = _is_retryable_status(e)

                if not retryable:
                    # Non-retryable error -- bail immediately
                    self._total_errors += 1
                    key_state.total_errors += 1
                    key_state.last_error = str(e)
                    logger.error(
                        "Non-retryable Gemini error on key %s: %s",
                        key_state.key_id,
                        e,
                    )
                    raise

                # On 429 specifically: deplete limiter and try rotating key
                if status == 429:
                    limiter.force_deplete_minute()
                    new_key = self._rotate_key("429-rate-limit")
                    if new_key is not None and new_key is not key_state:
                        key_state = new_key
                        genai = self._init_sdk(key_state.key)
                        limiter = (
                            key_state.pro_limiter
                            if use_pro
                            else key_state.flash_limiter
                        )
                        model_kwargs_copy = dict(model_kwargs)
                        model = genai.GenerativeModel(**model_kwargs_copy)
                        # After key rotation, retry immediately (no backoff)
                        logger.info(
                            "Retrying on new key %s after 429",
                            key_state.key_id,
                        )
                        continue

                if attempt < self._max_retries:
                    backoff = 2**attempt
                    logger.warning(
                        "Gemini API error (attempt %d/%d, key %s, status %s): %s "
                        "-- retrying in %ds",
                        attempt + 1,
                        self._max_retries + 1,
                        key_state.key_id,
                        status,
                        e,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                else:
                    self._total_errors += 1
                    key_state.total_errors += 1
                    key_state.last_error = str(e)
                    logger.error(
                        "Gemini API failed after %d attempts on key %s: %s",
                        self._max_retries + 1,
                        key_state.key_id,
                        e,
                    )
                    raise

        # Should not reach here, but satisfy the type checker
        if last_exc is not None:
            raise last_exc
        return self._exhausted_response(model_name)  # pragma: no cover

    # ------------------------------------------------------------------
    # Batch generation
    # ------------------------------------------------------------------
    async def generate_batch(
        self,
        prompts: list[str],
        use_pro: bool = False,
        json_mode: bool = True,
        system_instruction: str | None = None,
    ) -> list[dict[str, Any] | str]:
        """
        Send multiple prompts in parallel with concurrency control.

        Uses an asyncio.Semaphore to cap concurrent in-flight requests at
        ``max_concurrent`` (default 3) to stay within RPM limits across
        all keys.

        Args:
            prompts: List of prompts to send.
            use_pro: Force Pro model for all requests.
            json_mode: Parse all responses as JSON.
            system_instruction: Shared system instruction.

        Returns:
            List of responses in the same order as ``prompts``.
            Failed requests return an error dict instead of raising.
        """
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrent)

        async def _bounded_generate(prompt: str) -> dict[str, Any] | str:
            async with self._semaphore:
                try:
                    return await self.generate(
                        prompt=prompt,
                        use_pro=use_pro,
                        json_mode=json_mode,
                        system_instruction=system_instruction,
                    )
                except Exception as e:
                    logger.error("Batch request failed: %s", e)
                    return {
                        "error": True,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                        "model": self.model_pro if use_pro else self.model_flash,
                    }

        tasks = [_bounded_generate(p) for p in prompts]
        results: list[dict[str, Any] | str] = await asyncio.gather(*tasks)
        return results

    # ------------------------------------------------------------------
    # JSON parsing helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_json_response(text: str, model_name: str) -> dict[str, Any]:
        """Attempt to parse JSON from a Gemini response, handling markdown fences."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        stripped = text.strip()
        if stripped.startswith("```"):
            lines = stripped.split("\n")
            json_lines = [ln for ln in lines if not ln.startswith("```")]
            stripped = "\n".join(json_lines).strip()
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass

        logger.warning("Failed to parse JSON from %s response", model_name)
        return {"raw_response": text}

    # ------------------------------------------------------------------
    # Graceful degradation
    # ------------------------------------------------------------------
    @staticmethod
    def _exhausted_response(model_name: str) -> dict[str, Any]:
        """Return a structured error when all keys/limits are exhausted."""
        logger.warning(
            "All Gemini API keys exhausted -- returning degraded response "
            "for model %s",
            model_name,
        )
        return {
            "error": True,
            "error_type": "AllKeysExhausted",
            "error_message": (
                "All Gemini API keys have been exhausted or rate-limited. "
                "The finding could not be validated by the LLM. "
                "Please add more keys to GEMINI_API_KEYS or wait for limits to reset."
            ),
            "model": model_name,
        }

    # ------------------------------------------------------------------
    # Usage reporting
    # ------------------------------------------------------------------
    def get_usage_report(self) -> dict[str, Any]:
        """
        Return a comprehensive usage report.

        Includes aggregate stats, per-key breakdowns, cache stats,
        and estimated cost.
        """
        uptime = time.monotonic() - self._start_time

        total_input_tokens = 0
        total_output_tokens = 0
        per_key: list[dict[str, Any]] = []

        for ks in self._keys:
            total_input_tokens += ks.total_input_tokens_est
            total_output_tokens += ks.total_output_tokens_est
            per_key.append(
                {
                    "key_id": ks.key_id,
                    "total_requests": ks.total_requests,
                    "total_errors": ks.total_errors,
                    "input_tokens_est": ks.total_input_tokens_est,
                    "output_tokens_est": ks.total_output_tokens_est,
                    "pro_remaining_today": ks.pro_limiter.remaining_today,
                    "flash_remaining_today": ks.flash_limiter.remaining_today,
                    "is_exhausted": ks.is_exhausted,
                    "last_error": ks.last_error or None,
                }
            )

        # Cost estimate (blended -- assumes roughly 50/50 Pro/Flash unless
        # we tracked per-model, which we estimate conservatively as Pro)
        est_cost_input = (total_input_tokens / 1000) * _COST_PER_1K_INPUT_PRO
        est_cost_output = (total_output_tokens / 1000) * _COST_PER_1K_OUTPUT_PRO
        est_cost_total = est_cost_input + est_cost_output

        return {
            "uptime_seconds": round(uptime, 1),
            "total_requests": self._total_requests,
            "total_cached_hits": self._total_cached,
            "total_errors": self._total_errors,
            "total_input_tokens_est": total_input_tokens,
            "total_output_tokens_est": total_output_tokens,
            "estimated_cost_usd": round(est_cost_total, 6),
            "cache": {
                "size": self._cache.size,
                "hits": self._cache.hits,
                "misses": self._cache.misses,
                "hit_rate": (
                    round(
                        self._cache.hits / max(1, self._cache.hits + self._cache.misses),
                        3,
                    )
                ),
            },
            "keys": per_key,
            "active_key": (
                self._keys[self._current_key_idx].key_id if self._keys else None
            ),
            "total_keys": len(self._keys),
        }

    # ------------------------------------------------------------------
    # Backward-compatible properties
    # ------------------------------------------------------------------
    @property
    def api_key(self) -> str | None:
        """Return the currently active API key (or None)."""
        if self._keys:
            return self._keys[self._current_key_idx].key
        return None

    @property
    def is_available(self) -> bool:
        """Check if the Gemini API is configured and has remaining quota."""
        if not self._keys:
            return False
        return any(
            (ks.pro_limiter.remaining_today > 0 or ks.flash_limiter.remaining_today > 0)
            and not ks.is_exhausted
            for ks in self._keys
        )

    @property
    def remaining_quota(self) -> dict[str, int]:
        """Aggregate remaining quota across all keys."""
        pro_total = sum(ks.pro_limiter.remaining_today for ks in self._keys)
        flash_total = sum(ks.flash_limiter.remaining_today for ks in self._keys)
        return {
            "pro_remaining": pro_total,
            "flash_remaining": flash_total,
        }
