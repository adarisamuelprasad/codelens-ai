"""Request and response models for the ai-service contract (docs/architecture.md).

JSON keys are camelCase (`prTitle`, `ruleId`, `suggestedFix`) to match
codelens-api. Size limits here are hard rejections (422); the prompt builder
truncates further so a large but valid request still fits the model's budget.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.alias_generators import to_camel

MIN_FINDINGS = 1
MAX_FINDINGS = 15
MAX_CONVENTIONS_CHARS = 4_000
MAX_SNIPPET_CHARS = 20_000

Category = Literal["security", "bug", "reliability", "testing", "maintainability"]
Severity = Literal["high", "medium", "low"]
Verdict = Literal["true_positive", "likely_false_positive"]

VERDICTS: tuple[str, ...] = ("true_positive", "likely_false_positive")


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class PrContext(_CamelModel):
    repo: str = Field(min_length=1, max_length=200)
    pr_title: str = Field(default="", max_length=1_000)
    conventions: str | None = Field(default=None, max_length=MAX_CONVENTIONS_CHARS)


class Finding(_CamelModel):
    id: str = Field(min_length=1, max_length=100)
    rule_id: str = Field(min_length=1, max_length=100)
    category: Category
    severity: Severity
    message: str = Field(min_length=1, max_length=2_000)
    rule_description: str = Field(default="", max_length=4_000)
    file: str = Field(min_length=1, max_length=500)
    line: int = Field(ge=1)
    snippet: str = Field(min_length=1, max_length=MAX_SNIPPET_CHARS)


class ExplainRequest(_CamelModel):
    context: PrContext
    findings: list[Finding] = Field(min_length=MIN_FINDINGS, max_length=MAX_FINDINGS)

    @model_validator(mode="after")
    def _unique_ids(self) -> ExplainRequest:
        # Results are matched back to findings by id, so ids must be unambiguous.
        ids = [finding.id for finding in self.findings]
        if len(ids) != len(set(ids)):
            raise ValueError("finding ids must be unique")
        return self


class ExplainResult(_CamelModel):
    id: str
    explanation: str
    suggested_fix: str
    verdict: Verdict
    verdict_reason: str


class ExplainResponse(BaseModel):
    model: str
    results: list[ExplainResult]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    provider: Literal["gemini", "groq", "none"]


class LLMExplanation(BaseModel):
    """The schema the model is asked to fill, one per finding.

    `verdict` is a plain string on purpose: an out-of-range value must reach
    `app.validation` and be rejected there, not crash the parser.
    """

    explanation: str = Field(
        description="Plain English, at most 120 words: what the problem is and why it matters here."
    )
    suggestedFix: str = Field(  # noqa: N815 - the key the model sees, matches the contract
        description="At most 20 lines: prose or a short code snippet showing the fix."
    )
    verdict: str = Field(description='Exactly "true_positive" or "likely_false_positive".')
    verdictReason: str = Field(  # noqa: N815
        description="At most 40 words: why this verdict."
    )
