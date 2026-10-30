package com.codelens.eval;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import com.codelens.analysis.Finding;
import com.codelens.analysis.JavaRules;
import com.codelens.diff.ChangedFile;

/**
 * Scores CodeLens's injection rules on the OWASP Benchmark v1.2 (a public,
 * labelled set of Java test cases, each either truly vulnerable or a decoy
 * that only looks vulnerable). Runs only when OWASP_BENCHMARK_DIR points at a
 * checkout; results go in docs/evaluation.md.
 *
 * Cases are split by number: even = development (rules may be tuned on it),
 * odd = held out (reported, never tuned on).
 */
class OwaspBenchmarkEval {

    private static final Map<String, String> RULE_FOR_CATEGORY = Map.of(
        "sqli", "SQL_INJECTION", "cmdi", "COMMAND_INJECTION");

    @Test
    void scoreInjectionRules() throws Exception {
        String dir = System.getenv("OWASP_BENCHMARK_DIR");
        assumeTrue(dir != null && !dir.isBlank(), "set OWASP_BENCHMARK_DIR to run");
        Path root = Path.of(dir);
        Path code = root.resolve("src/main/java/org/owasp/benchmark/testcode");
        List<String> rows = Files.readAllLines(root.resolve("expectedresults-1.2.csv"));

        JavaRules rules = new JavaRules();
        // [split][category] -> {tp, fp, tn, fn}
        Map<String, int[]> score = new LinkedHashMap<>();
        Map<String, Integer> strayAlarms = new LinkedHashMap<>();
        long started = System.nanoTime();
        int files = 0;
        for (String row : rows.subList(1, rows.size())) {
            String[] f = row.split(",");
            String name = f[0], category = f[1];
            boolean vulnerable = Boolean.parseBoolean(f[2]);
            String content = Files.readString(code.resolve(name + ".java"));
            int lines = content.split("\n", -1).length;
            Set<Integer> all = IntStream.rangeClosed(1, lines).boxed().collect(Collectors.toSet());
            List<Finding> found = rules.analyze(List.of(new ChangedFile(name + ".java", "added", content, all)));
            files++;
            Set<String> fired = found.stream().map(Finding::ruleId).collect(Collectors.toSet());

            String rule = RULE_FOR_CATEGORY.get(category);
            if (rule == null) {
                // A case about something else: any injection alarm here is noise.
                for (String r : RULE_FOR_CATEGORY.values()) if (fired.contains(r)) strayAlarms.merge(r, 1, Integer::sum);
                continue;
            }
            int number = Integer.parseInt(name.replaceAll("\\D", ""));
            String split = number % 2 == 0 ? "dev" : "heldout";
            int[] s = score.computeIfAbsent(split + " " + category, k -> new int[4]);
            boolean predicted = fired.contains(rule);
            if (predicted && vulnerable) s[0]++;
            else if (predicted) s[1]++;
            else if (!vulnerable) s[2]++;
            else s[3]++;
        }
        double ms = (System.nanoTime() - started) / 1e6;

        System.out.printf("OWASP files=%d, %.2f ms per file%n", files, ms / files);
        score.forEach((k, s) -> {
            double tpr = (double) s[0] / (s[0] + s[3]);
            double fpr = (double) s[1] / (s[1] + s[2]);
            double precision = s[0] + s[1] == 0 ? 0 : (double) s[0] / (s[0] + s[1]);
            System.out.printf("OWASP %-14s tp=%d fp=%d tn=%d fn=%d  TPR=%.3f FPR=%.3f precision=%.3f youden=%.3f%n",
                k, s[0], s[1], s[2], s[3], tpr, fpr, precision, tpr - fpr);
        });
        System.out.println("OWASP stray alarms on other categories: " + strayAlarms);
    }
}
