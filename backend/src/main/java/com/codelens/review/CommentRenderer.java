package com.codelens.review;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.codelens.analysis.Finding.Severity;
import com.codelens.diff.Languages;

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
            md.append("No issues found on the lines this PR changed (").append(files(r)).append(" analysed).\n");
            return appendCoverageNote(md, r).toString();
        }

        Map<Severity, Integer> counts = new TreeMap<>();
        shown.forEach(f -> counts.merge(f.severity, 1, Integer::sum));
        md.append("**").append(shown.size()).append(shown.size() == 1 ? " finding" : " findings").append("** on changed lines");
        if (!counts.isEmpty()) {
            md.append(": ");
            counts.forEach((s, n) -> md.append(n).append(' ').append(s.name().toLowerCase()).append(", "));
            md.setLength(md.length() - 2);
        }
        md.append(" (").append(files(r)).append(" analysed)\n\n");

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
                        md.append("Suggested fix:\n\n```").append(fence(f.file)).append('\n')
                            .append(f.suggestedFix.replace("```", "")).append("\n```\n\n");
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
        appendCoverageNote(md, r);
        md.append("\n<sub>Findings come from static rules (PMD, Semgrep and CodeLens's own) on lines this PR changed. "
            + "Explanations are AI-written; security findings are never auto-dismissed.</sub>\n");
        return md.toString();
    }

    private static String files(Review r) {
        return r.filesAnalyzed + (r.filesAnalyzed == 1 ? " file" : " files");
    }

    // Say so when a language went unchecked, rather than imply "no issues".
    private static StringBuilder appendCoverageNote(StringBuilder md, Review r) {
        if (r.semgrepMissing) {
            md.append("\n> Only Java and secret checks ran: Semgrep is not installed on this CodeLens server, "
                + "so the rules for this PR's other languages were skipped.\n");
        }
        return md;
    }

    /** Markdown fence tag for a file's language; none when unknown. */
    static String fence(String file) {
        String language = Languages.of(file);
        if (language == null || language.equals("dotenv") || language.equals("properties")) return "";
        return language;
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
