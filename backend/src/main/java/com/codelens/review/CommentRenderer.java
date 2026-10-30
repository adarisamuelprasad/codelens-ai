package com.codelens.review;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.codelens.analysis.Finding.Severity;

/** The single PR comment CodeLens keeps up to date (found again by MARKER). */
public final class CommentRenderer {

    public static final String MARKER = "<!-- codelens-ai -->";
    private static final int TABLE_ROWS = 20;

    private CommentRenderer() {}

    public static String render(Review r, String htmlBase) {
        List<FindingRecord> shown = r.findings.stream().filter(f -> !f.demoted()).toList();
        List<FindingRecord> demoted = r.findings.stream().filter(FindingRecord::demoted).toList();
        StringBuilder md = new StringBuilder(MARKER).append("\n### CodeLens review\n\n");

        if (r.findings.isEmpty()) {
            return md.append("No issues found on the lines this PR changed (")
                .append(r.filesAnalyzed).append(r.filesAnalyzed == 1 ? " Java file" : " Java files")
                .append(" analysed).\n").toString();
        }

        Map<Severity, Integer> counts = new TreeMap<>();
        shown.forEach(f -> counts.merge(f.severity, 1, Integer::sum));
        md.append("**").append(shown.size()).append(shown.size() == 1 ? " finding" : " findings").append("** on changed lines");
        if (!counts.isEmpty()) {
            md.append(": ");
            counts.forEach((s, n) -> md.append(n).append(' ').append(s.name().toLowerCase()).append(", "));
            md.setLength(md.length() - 2);
        }
        md.append(" (").append(r.filesAnalyzed).append(" Java files analysed)\n\n");

        if (!shown.isEmpty()) {
            md.append("| Severity | Rule | Where | What |\n|---|---|---|---|\n");
            shown.stream().limit(TABLE_ROWS).forEach(f -> md.append("| ").append(f.severity.name().toLowerCase())
                .append(" | `").append(f.ruleId).append("` | ").append(link(f, r, htmlBase))
                .append(" | ").append(cell(f.message)).append(" |\n"));
            if (shown.size() > TABLE_ROWS) md.append("\n").append(shown.size() - TABLE_ROWS).append(" more in the dashboard.\n");

            List<FindingRecord> explained = shown.stream().filter(f -> f.explanation != null).limit(TABLE_ROWS).toList();
            if (!explained.isEmpty()) {
                md.append("\n<details><summary>Explanations and suggested fixes</summary>\n\n");
                for (FindingRecord f : explained) {
                    md.append("**`").append(f.ruleId).append("` at ").append(link(f, r, htmlBase)).append("**\n\n")
                        .append(f.explanation).append("\n\n");
                    if (f.suggestedFix != null && !f.suggestedFix.isBlank()) {
                        md.append("Suggested fix:\n\n```java\n").append(f.suggestedFix.replace("```", "")).append("\n```\n\n");
                    }
                }
                md.append("</details>\n");
            }
        }

        if (!demoted.isEmpty()) {
            md.append("\n<details><summary>").append(demoted.size())
                .append(" likely false positive(s), kept for review</summary>\n\n");
            demoted.forEach(f -> md.append("- `").append(f.ruleId).append("` at ").append(link(f, r, htmlBase))
                .append(": ").append(cell(f.aiVerdictReason == null ? f.message : f.aiVerdictReason)).append("\n"));
            md.append("\n</details>\n");
        }
        md.append("\n<sub>Findings come from static rules (PMD and CodeLens) on lines this PR changed. "
            + "Explanations are AI-written; security findings are never auto-dismissed.</sub>\n");
        return md.toString();
    }

    private static String link(FindingRecord f, Review r, String htmlBase) {
        String label = f.file.substring(f.file.lastIndexOf('/') + 1) + ":" + f.line;
        if (r.headSha == null) return "`" + label + "`";
        return "[`" + label + "`](" + htmlBase + "/" + r.repo + "/blob/" + r.headSha + "/" + f.file + "#L" + f.line + ")";
    }

    private static String cell(String s) {
        return s == null ? "" : s.replace("|", "\\|").replace("\n", " ");
    }
}
