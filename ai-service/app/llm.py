"""Chat model factory and the per-finding explanation chain.

One LLM call per finding, run concurrently with at most MAX_IN_FLIGHT calls
in flight per request. Each finding ends in exactly one Outcome:

  ok           validated (and security-ruled) explanation
  invalid      the model answered, but the answer failed validation
  unavailable  the call itself failed or timed out

Provider packages are imported lazily inside `build_chat_model`, so the
service boots and answers /health with LLM_PROVIDER=none even when neither
langchain-google-genai nor langchain-groq is installed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Literal

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import Runnable
from pydantic import BaseModel

from app.config import Settings
from app.models import ExplainRequest, Finding, LLMExplanation, PrContext
from app.prompts import EXPLAIN_PROMPT, build_prompt_inputs
from app.validation import ValidatedExplanation, extract_json_object, validate_for_finding

# Room for a 120-word explanation, a 20-line fix and a 40-word reason as JSON,
# with slack. Validation rejects anything over the caps regardless.
MAX_OUTPUT_TOKENS = 1_024

# Per request. Free tiers rate-limit hard; 4 keeps a 15-finding PR moving
# without tripping them.
MAX_IN_FLIGHT = 4

OutcomeStatus = Literal["ok", "invalid", "unavailable"]


class LLMUnavailable(Exception):
    """The configured provider could not produce an answer (any cause)."""


@dataclass(frozen=True)
class Outcome:
    finding_id: str
    status: OutcomeStatus
    value: ValidatedExplanation | None = None
    reason: str | None = None


def build_chat_model(settings: Settings) -> BaseChatModel | None:
    """Return a chat model for the configured provider, or None if there is none.

    Constructing a model does not touch the network; only invoking it does.
    """
    provider = settings.effective_provider
    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(
            model=settings.llm_model,
            api_key=settings.provider_api_key,
            temperature=settings.llm_temperature,
            timeout=settings.llm_timeout_seconds,
            max_retries=1,
            max_output_tokens=MAX_OUTPUT_TOKENS,
            # gemini-2.5-flash "thinks" by default, which spends output tokens
            # and latency on a short structured answer. Off.
            thinking_budget=0,
        )
    if provider == "groq":
        from langchain_groq import ChatGroq

        return ChatGroq(
            model=settings.llm_model,
            api_key=settings.provider_api_key,
            temperature=settings.llm_temperature,
            timeout=settings.llm_timeout_seconds,
            max_retries=1,
            max_tokens=MAX_OUTPUT_TOKENS,
        )
    return None


def _structured_runnable(chat_model: Runnable) -> Runnable | None:
    """`with_structured_output(..., include_raw=True)` where the model supports it.

    include_raw keeps a parse failure from raising: the raw message comes back
    alongside it, and we fall back to reading JSON out of that.
    """
    method = getattr(chat_model, "with_structured_output", None)
    if method is None:
        return None
    try:
        return method(LLMExplanation, include_raw=True)
    except (NotImplementedError, ValueError, TypeError):
        return None


def _message_text(message: Any) -> str:
    if isinstance(message, BaseMessage):
        content = message.content
    else:
        content = message
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # content blocks (Gemini)
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "".join(parts)
    return ""


def candidate_from_output(output: Any) -> dict[str, Any] | None:
    """Pull the answer dict out of whatever the chain returned.

    Handles: a structured-output envelope {raw, parsed, parsing_error}, a
    parsed Pydantic model or dict, an AIMessage with tool calls, or plain text
    holding JSON.
    """
    if isinstance(output, dict) and "raw" in output and "parsed" in output:
        parsed = output.get("parsed")
        if parsed is not None:
            return candidate_from_output(parsed)
        return candidate_from_output(output.get("raw"))
    # Messages first: a LangChain message is itself a Pydantic model, so the
    # BaseModel branch below would otherwise dump the whole message envelope.
    if isinstance(output, BaseMessage):
        if isinstance(output, AIMessage) and output.tool_calls:
            args = output.tool_calls[0].get("args")
            if isinstance(args, dict):
                return args
        return extract_json_object(_message_text(output))
    if isinstance(output, BaseModel):
        return output.model_dump()
    if isinstance(output, dict):
        return output
    return extract_json_object(_message_text(output))


class FindingExplainer:
    """prompt | chat model, one call per finding, bounded concurrency, hard timeouts."""

    def __init__(
        self,
        chat_model: Runnable,
        model_name: str,
        timeout_seconds: float,
        max_in_flight: int = MAX_IN_FLIGHT,
    ) -> None:
        self.model_name = model_name
        self.timeout_seconds = timeout_seconds
        self.max_in_flight = max_in_flight
        structured = _structured_runnable(chat_model)
        self.uses_structured_output = structured is not None
        self._chain: Runnable = EXPLAIN_PROMPT | (
            structured if structured is not None else chat_model | StrOutputParser()
        )

    async def _call(self, context: PrContext, finding: Finding) -> Any:
        """One LLM call. Any failure, including a timeout, raises LLMUnavailable."""
        inputs = build_prompt_inputs(context, finding)
        try:
            return await asyncio.wait_for(self._chain.ainvoke(inputs), timeout=self.timeout_seconds)
        except Exception as exc:  # provider errors come in many types; all mean "unavailable"
            raise LLMUnavailable(type(exc).__name__) from exc

    async def explain_one(
        self, context: PrContext, finding: Finding, semaphore: asyncio.Semaphore
    ) -> Outcome:
        async with semaphore:
            try:
                output = await self._call(context, finding)
            except LLMUnavailable as exc:
                return Outcome(finding.id, "unavailable", reason=str(exc))

        result = validate_for_finding(candidate_from_output(output), finding.category)
        if not result.ok:
            return Outcome(finding.id, "invalid", reason=result.reason)
        return Outcome(finding.id, "ok", value=result.value)

    async def explain_all(self, request: ExplainRequest) -> list[Outcome]:
        """One Outcome per finding, in request order."""
        semaphore = asyncio.Semaphore(self.max_in_flight)
        return list(
            await asyncio.gather(
                *(self.explain_one(request.context, f, semaphore) for f in request.findings)
            )
        )


def build_explainer(settings: Settings) -> FindingExplainer | None:
    model = build_chat_model(settings)
    if model is None:
        return None
    return FindingExplainer(model, settings.llm_model, settings.llm_timeout_seconds)
