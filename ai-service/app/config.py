"""Runtime settings, read from environment variables.

Settings are read on every call to `get_settings()` rather than cached at
import time, so tests (and a restarted container) always see the current
environment. Reading a handful of env vars is cheap.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

SUPPORTED_PROVIDERS = ("gemini", "groq", "none")

DEFAULT_MODELS = {
    "gemini": "gemini-2.5-flash",
    "groq": "llama-3.3-70b-versatile",
}

# The env var that must hold the API key for each provider.
PROVIDER_KEY_ENV = {
    "gemini": "GOOGLE_API_KEY",
    "groq": "GROQ_API_KEY",
}


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    codelens_shared_key: str
    llm_provider: str
    llm_model: str
    provider_api_key: str
    llm_timeout_seconds: float
    llm_temperature: float

    @property
    def effective_provider(self) -> str:
        """The provider that can actually serve requests.

        A provider without its API key cannot answer, so it reports as "none"
        instead of pretending to be ready.
        """
        if self.llm_provider == "none" or not self.provider_api_key:
            return "none"
        return self.llm_provider


def get_settings() -> Settings:
    provider = os.environ.get("LLM_PROVIDER", "none").strip().lower() or "none"
    if provider not in SUPPORTED_PROVIDERS:
        provider = "none"

    key_env = PROVIDER_KEY_ENV.get(provider)
    api_key = os.environ.get(key_env, "").strip() if key_env else ""

    model = os.environ.get("LLM_MODEL", "").strip() or DEFAULT_MODELS.get(provider, "")

    return Settings(
        codelens_shared_key=os.environ.get("CODELENS_SHARED_KEY", ""),
        llm_provider=provider,
        llm_model=model,
        provider_api_key=api_key,
        llm_timeout_seconds=_float_env("LLM_TIMEOUT_SECONDS", 20.0),
        llm_temperature=_float_env("LLM_TEMPERATURE", 0.2),
    )
