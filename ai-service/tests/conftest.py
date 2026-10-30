"""Shared fixtures. No test touches the network or needs a real API key."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from app import main
from app.llm import FindingExplainer

TEST_KEY = "test-shared-key-123"

SQL_SNIPPET = (
    "40 |     public User find(String name) {\n"
    "41 |         Statement st = conn.createStatement();\n"
    '42 |         ResultSet rs = st.executeQuery("SELECT * FROM users WHERE name = \'" + name + "\'");\n'
    "43 |         return map(rs);"
)

NPE_SNIPPET = (
    "10 |     String label(Order o) {\n"
    "11 |         Customer c = repo.findById(o.customerId()).orElse(null);\n"
    "12 |         return c.getName().trim();\n"
    "13 |     }"
)

SQL_FINDING: dict[str, Any] = {
    "id": "f1",
    "ruleId": "SQL_INJECTION",
    "category": "security",
    "severity": "high",
    "message": "SQL built by string concatenation with a method parameter.",
    "ruleDescription": "Queries must use bind parameters, never concatenated input.",
    "file": "src/main/java/com/acme/UserRepository.java",
    "line": 42,
    "snippet": SQL_SNIPPET,
}

NPE_FINDING: dict[str, Any] = {
    "id": "f2",
    "ruleId": "NULL_DEREFERENCE",
    "category": "bug",
    "severity": "medium",
    "message": "Value from orElse(null) is dereferenced without a null check.",
    "ruleDescription": "A possibly-null value is dereferenced.",
    "file": "src/main/java/com/acme/OrderLabels.java",
    "line": 12,
    "snippet": NPE_SNIPPET,
}

VALID_BODY: dict[str, Any] = {
    "context": {
        "repo": "acme/shop",
        "prTitle": "Add user lookup by name",
        "conventions": "Use Optional instead of null. Repositories use JdbcTemplate.",
    },
    "findings": [SQL_FINDING, NPE_FINDING],
}


def reply(**overrides: Any) -> str:
    """A well-formed model answer as JSON text, with any field overridden."""
    answer = {
        "explanation": "The query concatenates `name` into SQL, so a crafted name can change the query.",
        "suggestedFix": 'st = conn.prepareStatement("SELECT * FROM users WHERE name = ?");\nst.setString(1, name);',
        "verdict": "true_positive",
        "verdictReason": "The parameter flows straight into the SQL string.",
    }
    answer.update(overrides)
    return json.dumps(answer)


def finding(base: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    out = copy.deepcopy(base)
    out.update(overrides)
    return out


def prompt_text(prompt_value: Any) -> str:
    return "\n".join(m.content for m in prompt_value.to_messages())


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("GOOGLE_API_KEY", "GROQ_API_KEY", "LLM_MODEL", "LLM_TIMEOUT_SECONDS", "LLM_TEMPERATURE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CODELENS_SHARED_KEY", TEST_KEY)
    monkeypatch.setenv("LLM_PROVIDER", "none")
    main._cached_explainer.cache_clear()
    yield
    main.app.dependency_overrides.clear()
    main._cached_explainer.cache_clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(main.app)


@pytest.fixture
def body() -> dict[str, Any]:
    return copy.deepcopy(VALID_BODY)


@pytest.fixture
def auth() -> dict[str, str]:
    return {"X-CodeLens-Key": TEST_KEY}


@pytest.fixture
def use_model() -> Callable[..., FindingExplainer]:
    """Install a FindingExplainer around any chat model (a fake one in tests)."""

    def install(
        chat_model: Any,
        model_name: str = "fake-model",
        timeout: float = 5.0,
        max_in_flight: int = 4,
    ) -> FindingExplainer:
        explainer = FindingExplainer(chat_model, model_name, timeout, max_in_flight)
        main.app.dependency_overrides[main.explainer_dependency] = lambda: explainer
        return explainer

    return install


@pytest.fixture
def use_responder(use_model: Callable[..., FindingExplainer]) -> Callable[..., FindingExplainer]:
    """Install a fake model whose answer is `fn(prompt_text)`; fn may raise."""

    def install(fn: Callable[[str], str], **kwargs: Any) -> FindingExplainer:
        return use_model(RunnableLambda(lambda pv: AIMessage(content=fn(prompt_text(pv)))), **kwargs)

    return install


@pytest.fixture
def use_reply(use_responder: Callable[..., FindingExplainer]) -> Callable[[str], FindingExplainer]:
    """Install a fake model that answers every finding with `text`."""

    def install(text: str) -> FindingExplainer:
        return use_responder(lambda _: text)

    return install
