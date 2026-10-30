package com.codelens.analysis;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.codelens.analysis.Finding.Category;
import com.codelens.diff.ChangedFile;

/**
 * Runs every analyzer over the PR's files and turns the raw output into what
 * a reviewer should see: only lines this PR touched, one finding per spot,
 * most severe first, capped.
 */
@Service
public class AnalysisPipeline {

    // When two rules flag the same thing, the more specific one wins.
    private static final Map<String, Set<String>> SUPERSEDES = Map.of(
        "SWALLOWED_EXCEPTION", Set.of("AvoidPrintStackTrace", "SystemPrintln"),
        "HARDCODED_SECRET", Set.of("HardCodedCryptoKey"),
        "UseEqualsToCompareStrings", Set.of("CompareObjectsWithEquals"));
    private static final int SUPERSEDE_WITHIN_LINES = 3;

    private final PmdAnalyzer pmd;
    private final JavaRules rules;
    private final MissingTestRule missingTests;
    private final int maxFindings;

    public AnalysisPipeline(PmdAnalyzer pmd, JavaRules rules, MissingTestRule missingTests,
                            @Value("${codelens.analysis.max-findings:50}") int maxFindings) {
        this.pmd = pmd;
        this.rules = rules;
        this.missingTests = missingTests;
        this.maxFindings = maxFindings;
    }

    public List<Finding> analyze(List<ChangedFile> files) {
        List<Finding> raw = new ArrayList<>();
        raw.addAll(pmd.analyze(files));
        raw.addAll(rules.analyze(files));
        raw.addAll(missingTests.analyze(files));
        return select(raw, files, maxFindings);
    }

    static List<Finding> select(List<Finding> raw, List<ChangedFile> files, int cap) {
        Map<String, ChangedFile> byPath = new LinkedHashMap<>();
        files.forEach(f -> byPath.put(f.path(), f));

        List<Finding> kept = new ArrayList<>();
        for (Finding x : raw) {
            ChangedFile f = byPath.get(x.file());
            if (f == null) continue;
            // MISSING_TEST already only fires for touched methods; everything
            // else must sit on a line this PR added or changed.
            if (!x.ruleId().equals("MISSING_TEST") && !f.addedLines().contains(x.line())) continue;
            // In tests, only real defects; unused locals and println are normal there.
            if (f.isTest() && x.category() != Category.SECURITY && x.category() != Category.BUG) continue;
            kept.add(x);
        }

        kept.removeIf(x -> kept.stream().anyMatch(y -> y != x
            && SUPERSEDES.getOrDefault(y.ruleId(), Set.of()).contains(x.ruleId())
            && y.file().equals(x.file()) && Math.abs(y.line() - x.line()) <= SUPERSEDE_WITHIN_LINES));

        // One finding per rule per line (PMD can report a rule twice on one line).
        Map<String, Finding> unique = new LinkedHashMap<>();
        for (Finding x : kept) unique.putIfAbsent(x.ruleId() + "|" + x.file() + "|" + x.line(), x);

        return unique.values().stream()
            .sorted(Comparator.comparingInt((Finding x) -> x.severity().rank())
                .thenComparing(Finding::file).thenComparingInt(Finding::line))
            .limit(cap)
            .toList();
    }
}
