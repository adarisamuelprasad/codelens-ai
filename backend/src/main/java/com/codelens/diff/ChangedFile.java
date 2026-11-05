package com.codelens.diff;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A file the PR touched, at the PR's head commit.
 *
 * @param addedLines lines in {@code content} this PR added or changed; for a
 *                   new file, every line
 */
public record ChangedFile(String path, String status, String content, Set<Integer> addedLines) {

    // Class-named test files, case-sensitive so Latest.java and Unit.java are not tests.
    private static final Pattern TEST_CLASS = Pattern.compile(
        ".*(Test|Tests|IT|Spec)\\.(java|kt|scala|groovy|cs|php|swift)$");
    // Test-file conventions of the other ecosystems CodeLens reads.
    private static final Pattern TEST_FILE = Pattern.compile(
        "(?i).*("
            + "(^|/)test_[^/]*\\.py|_test\\.py|(^|/)conftest\\.py"     // pytest
            + "|\\.(test|spec)\\.[cm]?[jt]sx?"                          // foo.test.ts, foo.spec.js
            + "|_test\\.go"                                             // go test
            + "|_(spec|test)\\.rb"                                      // rspec, minitest
            + "|_test\\.(c|cc|cpp|rs|exs|dart)"
            + ")$");
    private static final Pattern TEST_DIR = Pattern.compile(
        "(?i)(^|/)(src/test|tests?|__tests__|spec|testing|[^/]+\\.tests?)/");

    public boolean isTest() {
        return TEST_CLASS.matcher(path).matches() || TEST_FILE.matcher(path).matches()
            || TEST_DIR.matcher(path).find();
    }

    /** CodeLens's language name for this file, or null; see {@link Languages}. */
    public String language() {
        return Languages.of(path);
    }

    public boolean isJava() {
        return path.toLowerCase(Locale.ROOT).endsWith(".java");
    }
}
