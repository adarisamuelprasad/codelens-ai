package com.codelens.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import com.codelens.diff.ChangedFile;

/**
 * The rule pack against src/test/resources/semgrep-fixtures/. A line
 * "codelens-expect: RULE" means the next line must be reported with RULE; any
 * other finding in those files is a false positive and fails the test, so the
 * near misses written next to each hit are checked too.
 *
 * Needs Semgrep: on PATH, or CODELENS_SEMGREP_COMMAND pointing at it. Without
 * it the fixture test is skipped (not passed), and the parsing and catalog
 * tests still run.
 */
class SemgrepAnalyzerTest {

    private static final Pattern EXPECT = Pattern.compile("codelens-expect: (\\w+)");
    private static final Path FIXTURES = Path.of("src/test/resources/semgrep-fixtures");

    private static String command() {
        String env = System.getenv("CODELENS_SEMGREP_COMMAND");
        return env == null || env.isBlank() ? "semgrep" : env;
    }

    @Test
    void everyRuleInThePackMapsToACatalogRule() throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(SemgrepAnalyzer.RULES_RESOURCE)) {
            Map<String, Object> root = new Yaml().load(in);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> rules = (List<Map<String, Object>>) root.get("rules");
            assertTrue(rules.size() > 50, "rule pack loaded");
            for (Map<String, Object> rule : rules) {
                @SuppressWarnings("unchecked")
                Map<String, Object> meta = (Map<String, Object>) rule.get("metadata");
                String id = meta == null ? null : (String) meta.get("codelens_rule");
                assertTrue(id != null && RuleCatalog.CODELENS.containsKey(id),
                    rule.get("id") + " has codelens_rule " + id + ", which RuleCatalog.CODELENS does not define");
            }
        }
    }

    @Test
    void fixturesHitExactlyTheMarkedLines() throws IOException {
        SemgrepAnalyzer semgrep = new SemgrepAnalyzer(command(), 300);
        Assumptions.assumeTrue(semgrep.available(), "Semgrep is not installed; set CODELENS_SEMGREP_COMMAND");

        List<ChangedFile> files = new ArrayList<>();
        Set<String> expected = new TreeSet<>();
        try (Stream<Path> paths = Files.list(FIXTURES)) {
            for (Path p : paths.sorted().toList()) {
                String content = Files.readString(p, StandardCharsets.UTF_8);
                String[] lines = content.split("\n", -1);
                // Fixtures live under a test folder in a real PR too; give them app paths.
                String path = "app/" + p.getFileName();
                for (int i = 0; i < lines.length; i++) {
                    Matcher m = EXPECT.matcher(lines[i]);
                    if (m.find()) expected.add(path + ":" + (i + 2) + ":" + m.group(1));
                }
                Set<Integer> all = new java.util.HashSet<>();
                for (int i = 1; i <= lines.length; i++) all.add(i);
                files.add(new ChangedFile(path, "added", content, all));
            }
        }

        Set<String> actual = new TreeSet<>();
        for (Finding f : semgrep.analyze(files)) actual.add(f.file() + ":" + f.line() + ":" + f.ruleId());

        Set<String> missed = new TreeSet<>(expected);
        missed.removeAll(actual);
        Set<String> extra = new TreeSet<>(actual);
        extra.removeAll(expected);
        assertEquals(Set.of(), missed, "expected findings Semgrep did not report");
        assertEquals(Set.of(), extra, "findings no fixture asked for (false positives)");
    }

    @Test
    void testFoldersAreScannedLikeAnyOther() {
        SemgrepAnalyzer semgrep = new SemgrepAnalyzer(command(), 300);
        Assumptions.assumeTrue(semgrep.available(), "Semgrep is not installed; set CODELENS_SEMGREP_COMMAND");
        // Semgrep's defaults skip tests/; a leaked eval in a test still matters.
        List<Finding> found = semgrep.analyze(List.of(
            JavaRulesTest.file("tests/test_tools.py", "def f(x):\n    return eval(x)\n")));
        assertEquals(List.of("CODE_INJECTION"), found.stream().map(Finding::ruleId).toList());
        assertEquals("tests/test_tools.py", found.get(0).file());
        assertEquals(2, found.get(0).line());
    }

    @Test
    void parsesSemgrepJsonBackToPrPaths() throws IOException {
        Path src = Path.of("/tmp/codelens-semgrep-x/src").toAbsolutePath();
        ChangedFile f = JavaRulesTest.file("api/handlers/user.go", "package api\n");
        String json = """
            {"results": [
              {"check_id": "rules.sql-injection.go", "path": "%s",
               "start": {"line": 12}, "extra": {"message": "SQL   built\\n with Sprintf", "metadata": {"codelens_rule": "SQL_INJECTION"}}},
              {"check_id": "rules.unknown", "path": "%s",
               "start": {"line": 3}, "extra": {"message": "x", "metadata": {"codelens_rule": "NOT_A_RULE"}}},
              {"check_id": "rules.sql-injection.go", "path": "%s",
               "start": {"line": 4}, "extra": {"message": "outside", "metadata": {"codelens_rule": "SQL_INJECTION"}}}
            ], "errors": []}
            """.formatted(
                json(src.resolve("0/user.go")), json(src.resolve("0/user.go")), json(src.resolve("../elsewhere/user.go")));

        List<Finding> out = new SemgrepAnalyzer("", 60).parse(json, src, Map.of("0/user.go", f));
        assertEquals(1, out.size());
        Finding x = out.get(0);
        assertEquals("SQL_INJECTION", x.ruleId());
        assertEquals("semgrep", x.source());
        assertEquals("api/handlers/user.go", x.file());
        assertEquals(12, x.line());
        assertEquals("SQL built with Sprintf", x.message());
        assertEquals(Finding.Severity.HIGH, x.severity());
    }

    @Test
    void missingSemgrepMeansNoFindingsNotAFailedReview() {
        SemgrepAnalyzer absent = new SemgrepAnalyzer("codelens-no-such-semgrep-binary", 10);
        assertFalse(absent.available());
        assertEquals(List.of(), absent.analyze(List.of(JavaRulesTest.file("a.py", "eval(x)\n"))));
        assertFalse(new SemgrepAnalyzer("", 10).available());
    }

    private static String json(Path p) {
        return p.toString().replace("\\", "\\\\");
    }
}
