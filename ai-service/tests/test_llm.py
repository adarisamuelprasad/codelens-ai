"""Provider factory, settings, structured output handling, and the concurrency limit."""

from __future__ import annotations

import asyncio
import copy
import json
from typing import Any

from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from app.config import get_settings
from app.llm import MAX_IN_FLIGHT, FindingExplainer, build_chat_model, build_explainer, candidate_from_output
from app.models import ExplainRequest, LLMExplanation
from tests.conftest import NPE_FINDING, VALID_BODY, finding, reply

# ---------------------------------------------------------------- factory and settings


def test_none_provider_builds_nothing():
    assert build_chat_model(get_settings()) is None
    assert build_explainer(get_settings()) is None


def test_unknown_provider_is_treated_as_none(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    settings = get_settings()
    assert settings.llm_provider == "none"
    assert build_chat_model(settings) is None


def test_provider_without_key_builds_nothing(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    assert build_chat_model(get_settings()) is None


def test_gemini_defaults_use_structured_output(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "Gemini")
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-google-key")
    model = build_chat_model(get_settings())
    assert type(model).__name__ == "ChatGoogleGenerativeAI"
    assert model.model.endswith("gemini-2.5-flash")
    explainer = build_explainer(get_settings())
    assert explainer.model_name == "gemini-2.5-flash"
    assert explainer.uses_structured_output


def test_groq_defaults_and_model_override(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_fake")
    assert build_chat_model(get_settings()).model_name == "llama-3.3-70b-versatile"
    monkeypatch.setenv("LLM_MODEL", "llama-3.1-8b-instant")
    model = build_chat_model(get_settings())
    assert type(model).__name__ == "ChatGroq"
    assert model.model_name == "llama-3.1-8b-instant"
    assert build_explainer(get_settings()).uses_structured_output


def test_timeout_and_temperature_from_env(monkeypatch):
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "9")
    monkeypatch.setenv("LLM_TEMPERATURE", "not-a-number")
    settings = get_settings()
    assert settings.llm_timeout_seconds == 9.0
    assert settings.llm_temperature == 0.2


def test_model_without_structured_output_falls_back_to_json_text():
    explainer = FindingExplainer(FakeListChatModel(responses=[reply()]), "fake", 5.0)
    assert not explainer.uses_structured_output


# ---------------------------------------------------------------- output shapes


def test_candidate_from_structured_envelope_with_parsed_model():
    parsed = LLMExplanation(explanation="e", suggestedFix="f", verdict="true_positive", verdictReason="r")
    out = candidate_from_output({"raw": AIMessage(content=""), "parsed": parsed, "parsing_error": None})
    assert out == {"explanation": "e", "suggestedFix": "f", "verdict": "true_positive", "verdictReason": "r"}


def test_candidate_from_envelope_with_parse_error_uses_tool_call_args():
    raw = AIMessage(
        content="",
        tool_calls=[{"name": "LLMExplanation", "args": {"verdict": "nope"}, "id": "c1"}],
    )
    out = candidate_from_output({"raw": raw, "parsed": None, "parsing_error": ValueError("bad")})
    assert out == {"verdict": "nope"}


def test_candidate_from_envelope_with_parse_error_reads_raw_json_text():
    raw = AIMessage(content='```json\n{"verdict": "true_positive"}\n```')
    out = candidate_from_output({"raw": raw, "parsed": None, "parsing_error": ValueError("bad")})
    assert out == {"verdict": "true_positive"}


def test_candidate_from_content_blocks():
    msg = AIMessage(content=[{"type": "text", "text": '{"a": '}, {"type": "text", "text": "1}"}])
    assert candidate_from_output(msg) == {"a": 1}


class _StructuredFake(FakeListChatModel):
    """A fake model whose with_structured_output returns a canned envelope."""

    def with_structured_output(self, schema: Any, *, include_raw: bool = False, **kwargs: Any):
        assert schema is LLMExplanation and include_raw
        parsed = LLMExplanation.model_validate_json(self.responses[0])
        return RunnableLambda(lambda _: {"raw": AIMessage(content=""), "parsed": parsed, "parsing_error": None})


def test_structured_output_path_end_to_end():
    explainer = FindingExplainer(
        _StructuredFake(responses=[reply(verdict="likely_false_positive")]), "fake", 5.0
    )
    assert explainer.uses_structured_output
    request = ExplainRequest.model_validate(VALID_BODY)
    outcomes = asyncio.run(explainer.explain_all(request))
    assert [o.status for o in outcomes] == ["ok", "ok"]
    # Security rule applies on this path too.
    assert outcomes[0].value.verdict == "true_positive"
    assert outcomes[1].value.verdict == "likely_false_positive"


# ---------------------------------------------------------------- concurrency


def _request_with(n: int) -> ExplainRequest:
    body = copy.deepcopy(VALID_BODY)
    body["findings"] = [finding(NPE_FINDING, id=f"f{i}") for i in range(n)]
    return ExplainRequest.model_validate(body)


def _counting_model(stats: dict[str, int]) -> RunnableLambda:
    async def call(_prompt):
        stats["active"] += 1
        stats["peak"] = max(stats["peak"], stats["active"])
        stats["calls"] += 1
        await asyncio.sleep(0.02)
        stats["active"] -= 1
        return AIMessage(content=reply())

    return RunnableLambda(call)


def test_at_most_four_calls_in_flight():
    stats = {"active": 0, "peak": 0, "calls": 0}
    explainer = FindingExplainer(_counting_model(stats), "fake", 5.0)
    outcomes = asyncio.run(explainer.explain_all(_request_with(15)))
    assert stats["calls"] == 15
    assert stats["peak"] == MAX_IN_FLIGHT == 4
    assert all(o.status == "ok" for o in outcomes)


def test_calls_do_run_concurrently_and_limit_is_configurable():
    stats = {"active": 0, "peak": 0, "calls": 0}
    explainer = FindingExplainer(_counting_model(stats), "fake", 5.0, max_in_flight=2)
    asyncio.run(explainer.explain_all(_request_with(6)))
    assert stats["peak"] == 2


def test_outcomes_keep_request_order_and_statuses():
    async def call(pv):
        text = pv.to_string()
        if "Flagged line: 1\n" in text:
            raise RuntimeError("down")
        if "Flagged line: 2\n" in text:
            return AIMessage(content=json.dumps({"explanation": ""}))
        return AIMessage(content=reply())

    body = copy.deepcopy(VALID_BODY)
    body["findings"] = [finding(NPE_FINDING, id=f"f{i}", line=i) for i in (1, 2, 3)]
    explainer = FindingExplainer(RunnableLambda(call), "fake", 5.0)
    outcomes = asyncio.run(explainer.explain_all(ExplainRequest.model_validate(body)))
    assert [(o.finding_id, o.status) for o in outcomes] == [
        ("f1", "unavailable"),
        ("f2", "invalid"),
        ("f3", "ok"),
    ]
    assert outcomes[1].reason == "missing_field"
