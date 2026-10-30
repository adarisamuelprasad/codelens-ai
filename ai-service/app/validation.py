"""Per-finding validation of LLM output. Pure functions, no I/O, no LangChain.

An item that fails any check is dropped from `results`; codelens-api then
keeps the rule's own message for that finding. Nothing is truncated to make
it fit: an over-long answer is a sign the model ignored the instructions, and
a silently cut explanation can end mid-sentence or mid-fix.

Checks, in order:
  not_an_object         no JSON object could be read from the output
  missing_field         one of the four keys is absent or not a string
  empty_explanation     explanation is blank
  explanation_too_long  over MAX_EXPLANATION_WORDS words (or MAX_EXPLANATION_CHARS)
  fix_too_long          suggestedFix over MAX_FIX_LINES lines (or MAX_FIX_CHARS)
  invalid_verdict       verdict is not exactly one of VERDICTS
  empty_verdict_reason  verdictReason is blank
  reason_too_long       over MAX_REASON_WORDS words (or MAX_REASON_CHARS)

Then the security rule: a `security` finding is never demoted. If the model
said `likely_false_positive`, the verdict becomes `true_positive` and the
reason says why. codelens-api enforces the same rule; this is defence in depth.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from app.models import VERDICTS

MAX_EXPLANATION_WORDS = 120
MAX_EXPLANATION_CHARS = 1_200
MAX_FIX_LINES = 20
MAX_FIX_CHARS = 2_000
MAX_REASON_WORDS = 40
MAX_REASON_CHARS = 400

REASON_NOT_AN_OBJECT = "not_an_object"
REASON_MISSING_FIELD = "missing_field"
REASON_EMPTY_EXPLANATION = "empty_explanation"
REASON_EXPLANATION_TOO_LONG = "explanation_too_long"
REASON_FIX_TOO_LONG = "fix_too_long"
REASON_INVALID_VERDICT = "invalid_verdict"
REASON_EMPTY_VERDICT_REASON = "empty_verdict_reason"
REASON_REASON_TOO_LONG = "reason_too_long"

SECURITY_OVERRIDE_REASON = "Security findings are never auto-dismissed; review manually."

# Accepted spellings of each output key; the first is canonical.
_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "explanation": ("explanation",),
    "suggestedFix": ("suggestedFix", "suggested_fix"),
    "verdict": ("verdict",),
    "verdictReason": ("verdictReason", "verdict_reason"),
}

# A line that is only a fence marker: ``` / ```java / ~~~ / ~~~python
_FENCE_LINE = re.compile(r"^\s*(?:```+|~~~+)\s*[\w.+#-]*\s*$")
_OUTER_JSON_FENCE = re.compile(r"^\s*```[\w-]*\s*\n(.*)\n\s*```\s*$", re.DOTALL)


@dataclass(frozen=True)
class ValidatedExplanation:
    explanation: str
    suggested_fix: str
    verdict: str
    verdict_reason: str


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    value: ValidatedExplanation | None = None
    reason: str | None = None


def _reject(reason: str) -> ValidationResult:
    return ValidationResult(ok=False, reason=reason)


def extract_json_object(text: str | None) -> dict[str, Any] | None:
    """Read one JSON object from model text: bare, fenced, or wrapped in prose.

    Returns None when there is no parseable object.
    """
    if not text or not text.strip():
        return None
    candidate = text.strip()
    fenced = _OUTER_JSON_FENCE.match(candidate)
    if fenced:
        candidate = fenced.group(1).strip()

    try:
        parsed = json.loads(candidate)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        return parsed

    # Prose around the object: try every '{' until one decodes to a dict.
    decoder = json.JSONDecoder()
    for start in (i for i, ch in enumerate(candidate) if ch == "{"):
        try:
            obj, _ = decoder.raw_decode(candidate, start)
        except ValueError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def strip_fences(text: str) -> str:
    """Remove markdown fence lines, keeping the code they wrapped.

    "```java\\nfoo();\\n```" becomes "foo();". Prose around a fenced block
    survives; only the marker lines go.
    """
    lines = [line.rstrip() for line in text.splitlines() if not _FENCE_LINE.match(line)]
    # Drop leading and trailing blank lines left behind.
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def _word_count(text: str) -> int:
    return len(text.split())


def _get_field(candidate: dict[str, Any], canonical: str) -> str | None:
    for key in _FIELD_ALIASES[canonical]:
        value = candidate.get(key)
        if isinstance(value, str):
            return value
    return None


def validate_explanation(candidate: Any) -> ValidationResult:
    """Validate one model answer (already parsed into a dict). Never raises."""
    if not isinstance(candidate, dict):
        return _reject(REASON_NOT_AN_OBJECT)

    fields = {name: _get_field(candidate, name) for name in _FIELD_ALIASES}
    if any(value is None for value in fields.values()):
        return _reject(REASON_MISSING_FIELD)

    explanation = " ".join(fields["explanation"].split())  # type: ignore[union-attr]
    if not explanation:
        return _reject(REASON_EMPTY_EXPLANATION)
    if _word_count(explanation) > MAX_EXPLANATION_WORDS or len(explanation) > MAX_EXPLANATION_CHARS:
        return _reject(REASON_EXPLANATION_TOO_LONG)

    fix = strip_fences(fields["suggestedFix"])  # type: ignore[arg-type]
    if len(fix.splitlines()) > MAX_FIX_LINES or len(fix) > MAX_FIX_CHARS:
        return _reject(REASON_FIX_TOO_LONG)

    verdict = fields["verdict"].strip()  # type: ignore[union-attr]
    if verdict not in VERDICTS:
        return _reject(REASON_INVALID_VERDICT)

    reason = " ".join(fields["verdictReason"].split())  # type: ignore[union-attr]
    if not reason:
        return _reject(REASON_EMPTY_VERDICT_REASON)
    if _word_count(reason) > MAX_REASON_WORDS or len(reason) > MAX_REASON_CHARS:
        return _reject(REASON_REASON_TOO_LONG)

    return ValidationResult(
        ok=True,
        value=ValidatedExplanation(
            explanation=explanation,
            suggested_fix=fix,
            verdict=verdict,
            verdict_reason=reason,
        ),
    )


def apply_security_rule(value: ValidatedExplanation, category: str) -> ValidatedExplanation:
    """A security finding is never demoted, whatever the model said."""
    if category != "security" or value.verdict == "true_positive":
        return value
    return ValidatedExplanation(
        explanation=value.explanation,
        suggested_fix=value.suggested_fix,
        verdict="true_positive",
        verdict_reason=SECURITY_OVERRIDE_REASON,
    )


def validate_for_finding(candidate: Any, category: str) -> ValidationResult:
    """Validation plus the security rule: the single entry point the API uses."""
    result = validate_explanation(candidate)
    if not result.ok or result.value is None:
        return result
    return ValidationResult(ok=True, value=apply_security_rule(result.value, category))
