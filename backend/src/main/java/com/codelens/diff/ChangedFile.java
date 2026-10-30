package com.codelens.diff;

import java.util.Set;

/**
 * A Java file the PR touched, at the PR's head commit.
 *
 * @param addedLines lines in {@code content} this PR added or changed; for a
 *                   new file, every line
 */
public record ChangedFile(String path, String status, String content, Set<Integer> addedLines) {

    public boolean isTest() {
        return path.contains("/src/test/") || path.startsWith("src/test/") || path.endsWith("Test.java")
            || path.endsWith("Tests.java") || path.endsWith("IT.java");
    }
}
