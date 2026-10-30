"""Pure validation: field checks, caps, fence stripping, JSON extraction, security rule."""

from __future__ import annotations

import pytest

from app.validation import (
    MAX_EXPLANATION_WORDS,
    MAX_FIX_LINES,
    MAX_REASON_WORDS,
    REASON_EMPTY_EXPLANATION,
    REASON_EMPTY_VERDICT_REASON,
    REASON_EXPLANATION_TOO_LONG,
    REASON_FIX_TOO_LONG,
    REASON_INVALID_VERDICT,
    REASON_MISSING_FIELD,
    REASON_NOT_AN_OBJECT,
    REASON_REASON_TOO_LONG,
    SECURITY_OVERRIDE_REASON,
    ValidatedExplanation,
    apply_security_rule,
    extract_json_object,
    strip_fences,
    validate_explanation,
    validate_for_finding,
)


def answer(**overrides):
    base = {
        "explanation": "The loop reads past the end of the array.",
        "suggestedFix": "Use `i < n` instead of `i <= n`.",
        "verdict": "true_positive",
        "verdictReason": "The bound is off by one.",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------- accepts


def test_valid_answer_passes_cleaned():
    result = validate_explanation(answer(explanation="  The loop\n reads   past the end.  "))
    assert result.ok
    assert result.value.explanation == "The loop reads past the end."
    assert result.value.verdict == "true_positive"


def test_snake_case_keys_are_accepted():
    data = answer()
    data["suggested_fix"] = data.pop("suggestedFix")
    data["verdict_reason"] = data.pop("verdictReason")
    assert validate_explanation(data).ok


def test_empty_fix_is_allowed():
    result = validate_explanation(answer(suggestedFix="   "))
    assert result.ok
    assert result.value.suggested_fix == ""


@pytest.mark.parametrize(
    "words, ok", [(MAX_EXPLANATION_WORDS, True), (MAX_EXPLANATION_WORDS + 1, False)]
)
def test_explanation_word_cap_boundary(words, ok):
    assert validate_explanation(answer(explanation="word " * words)).ok is ok


@pytest.mark.parametrize("lines, ok", [(MAX_FIX_LINES, True), (MAX_FIX_LINES + 1, False)])
def test_fix_line_cap_boundary(lines, ok):
    fix = "\n".join(f"line{i};" for i in range(lines))
    assert validate_explanation(answer(suggestedFix=fix)).ok is ok


@pytest.mark.parametrize("words, ok", [(MAX_REASON_WORDS, True), (MAX_REASON_WORDS + 1, False)])
def test_reason_word_cap_boundary(words, ok):
    assert validate_explanation(answer(verdictReason="word " * words)).ok is ok


# ---------------------------------------------------------------- rejects


@pytest.mark.parametrize(
    ("candidate", "reason"),
    [
        (None, REASON_NOT_AN_OBJECT),
        ("a string", REASON_NOT_AN_OBJECT),
        (["list"], REASON_NOT_AN_OBJECT),
        ({"explanation": "x"}, REASON_MISSING_FIELD),
        (answer(verdict=None), REASON_MISSING_FIELD),
        (answer(explanation=42), REASON_MISSING_FIELD),
        (answer(explanation="   \n "), REASON_EMPTY_EXPLANATION),
        (answer(explanation="x" * 1_201), REASON_EXPLANATION_TOO_LONG),
        (answer(suggestedFix="y" * 2_001), REASON_FIX_TOO_LONG),
        (answer(verdict="false_positive"), REASON_INVALID_VERDICT),
        (answer(verdict="TRUE_POSITIVE"), REASON_INVALID_VERDICT),
        (answer(verdict="true_positive, probably"), REASON_INVALID_VERDICT),
        (answer(verdict=""), REASON_INVALID_VERDICT),
        (answer(verdictReason=" "), REASON_EMPTY_VERDICT_REASON),
        (answer(verdictReason="z" * 401), REASON_REASON_TOO_LONG),
    ],
)
def test_rejections(candidate, reason):
    result = validate_explanation(candidate)
    assert not result.ok
    assert result.reason == reason
    assert result.value is None


def test_over_long_text_is_rejected_not_truncated():
    result = validate_explanation(answer(explanation="word " * 500))
    assert not result.ok
    assert result.value is None


def test_fence_lines_do_not_count_toward_fix_cap():
    body = "\n".join(f"line{i};" for i in range(MAX_FIX_LINES))
    result = validate_explanation(answer(suggestedFix=f"```java\n{body}\n```"))
    assert result.ok
    assert result.value.suggested_fix == body


# ---------------------------------------------------------------- fences


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("```java\nfoo();\n```", "foo();"),
        ("```\nfoo();\nbar();\n```", "foo();\nbar();"),
        ("~~~python\nx = 1\n~~~", "x = 1"),
        ("Use a prepared statement:\n```java\nps.setString(1, name);\n```", "Use a prepared statement:\nps.setString(1, name);"),
        ("plain prose, no fences", "plain prose, no fences"),
        ("\n\n  indented();\n\n", "  indented();"),
    ],
)
def test_strip_fences(raw, expected):
    assert strip_fences(raw) == expected


def test_inline_backticks_survive():
    assert strip_fences("Call `close()` in a finally block.") == "Call `close()` in a finally block."


# ---------------------------------------------------------------- JSON extraction


def test_extract_bare_json():
    assert extract_json_object('{"verdict": "true_positive"}') == {"verdict": "true_positive"}


def test_extract_fenced_json():
    assert extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}


def test_extract_json_wrapped_in_prose():
    assert extract_json_object('Here you go: {"a": {"b": 2}} hope it helps') == {"a": {"b": 2}}


def test_extract_skips_braces_that_are_not_json():
    assert extract_json_object('if (x) { y(); } then {"a": 1}') == {"a": 1}


@pytest.mark.parametrize("text", [None, "", "   ", "no json here", "[1, 2]", '{"a": '])
def test_extract_returns_none_without_an_object(text):
    assert extract_json_object(text) is None


# ---------------------------------------------------------------- security rule


def _value(verdict: str, reason: str = "Model reason.") -> ValidatedExplanation:
    return ValidatedExplanation("Explained.", "Fix it.", verdict, reason)


def test_security_false_positive_is_forced():
    forced = apply_security_rule(_value("likely_false_positive"), "security")
    assert forced.verdict == "true_positive"
    assert forced.verdict_reason == SECURITY_OVERRIDE_REASON
    assert forced.explanation == "Explained."


def test_security_true_positive_keeps_model_reason():
    kept = apply_security_rule(_value("true_positive", "Concatenated input."), "security")
    assert kept.verdict_reason == "Concatenated input."


@pytest.mark.parametrize("category", ["bug", "reliability", "testing", "maintainability"])
def test_other_categories_may_be_demoted(category):
    assert apply_security_rule(_value("likely_false_positive"), category).verdict == "likely_false_positive"


def test_validate_for_finding_applies_rule_after_validation():
    result = validate_for_finding(answer(verdict="likely_false_positive"), "security")
    assert result.ok
    assert result.value.verdict == "true_positive"
    assert result.value.verdict_reason == SECURITY_OVERRIDE_REASON


def test_validate_for_finding_still_rejects_invalid_security_answer():
    result = validate_for_finding(answer(verdict="dismiss"), "security")
    assert not result.ok
    assert result.reason == REASON_INVALID_VERDICT
