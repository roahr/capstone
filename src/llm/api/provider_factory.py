"""
LLM Provider Factory: Creates the right client based on .env configuration.

Environment variables:
    LLM_PROVIDER    Provider name: "gemini" (default) or "groq"
    LLM_MODEL       Override the primary model name (optional)
    GEMINI_API_KEY   Gemini API key (when provider=gemini)
    GROQ_API_KEY     Groq API key (when provider=groq)

Usage:
    from src.llm.api.provider_factory import create_llm_client
    client = create_llm_client(config)
"""

from __future__ import annotations

import logging
import os
from typing import Any

from src.llm.api.base_client import BaseLLMClient

logger = logging.getLogger(__name__)

# Supported providers and their env key names
PROVIDERS = {
    "gemini": {
        "client_class": "src.llm.api.gemini_client.GeminiClient",
        "api_key_env": "GEMINI_API_KEY",
        "default_model": "gemini-2.5-flash",
        "description": "Google Gemini 2.5 (Flash: 500 RPD free tier)",
    },
    "groq": {
        "client_class": "src.llm.api.groq_client.GroqClient",
        "api_key_env": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
        "description": "Groq LPU (Llama 3.3 70B: 1000 RPD free tier)",
    },
}


def create_llm_client(config: dict[str, Any] | None = None) -> BaseLLMClient | None:
    """
    Create an LLM client based on environment configuration.

    Reads LLM_PROVIDER from environment (default: "gemini").
    Returns None if the provider's API key is not set.

    Args:
        config: Provider-specific configuration (from default.yaml llm section)

    Returns:
        Configured BaseLLMClient instance, or None if unavailable
    """
    config = config or {}
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower().strip()

    if provider not in PROVIDERS:
        logger.error(
            "Unknown LLM_PROVIDER '%s'. Supported: %s",
            provider, ", ".join(PROVIDERS.keys()),
        )
        return None

    provider_info = PROVIDERS[provider]

    # Check for API key (single or multi-key)
    api_key = os.environ.get(provider_info["api_key_env"])
    multi_key_env = provider_info["api_key_env"] + "S"  # e.g., GEMINI_API_KEYS, GROQ_API_KEYS
    multi_keys = os.environ.get(multi_key_env, "")

    if not api_key and not multi_keys:
        logger.warning(
            "LLM provider '%s' selected but %s (or %s) not set. LLM stage disabled.",
            provider, provider_info["api_key_env"], multi_key_env,
        )
        return None

    logger.debug(
        "LLM provider: %s (%s)",
        provider, provider_info["description"],
    )

    # Model override from env
    env_model = os.environ.get("LLM_MODEL")

    if provider == "gemini":
        from src.llm.api.gemini_client import GeminiClient

        gemini_config = config.get("gemini", config)
        if env_model:
            gemini_config["model_flash"] = env_model
            gemini_config["model_pro"] = env_model
        client = GeminiClient(gemini_config)
        return client

    elif provider == "groq":
        from src.llm.api.groq_client import GroqClient

        groq_config = config.get("groq", {})
        # Merge top-level LLM config
        for key in ("temperature", "max_output_tokens", "max_retries", "cache_size"):
            if key in config.get("gemini", {}):
                groq_config.setdefault(key, config["gemini"][key])
        if env_model:
            groq_config["model_pro"] = env_model
            groq_config["model_flash"] = env_model
        client = GroqClient(groq_config)
        return client

    return None


def get_provider_status() -> dict[str, Any]:
    """Get status of all configured LLM providers for the status display."""
    status = {}
    for name, info in PROVIDERS.items():
        key = os.environ.get(info["api_key_env"])
        status[name] = {
            "configured": bool(key),
            "api_key_env": info["api_key_env"],
            "key_preview": f"...{key[-4:]}" if key and len(key) > 4 else None,
            "default_model": info["default_model"],
            "description": info["description"],
        }

    active = os.environ.get("LLM_PROVIDER", "gemini").lower()
    status["active_provider"] = active

    return status
