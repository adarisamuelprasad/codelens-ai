package com.codelens.analysis;

/**
 * One issue a rule found. Category and severity come from {@link RuleCatalog},
 * never from the LLM, so the same code always gets the same verdict.
 */
public record Finding(
    String ruleId,
    String source,          // "pmd" or "codelens"
    Category category,
    Severity severity,
    String file,
    int line,
    String message
) {

    public enum Category { SECURITY, BUG, RELIABILITY, TESTING, MAINTAINABILITY }

    public enum Severity {
        HIGH, MEDIUM, LOW;

        public int rank() {
            return ordinal(); // HIGH sorts first
        }
    }
}
