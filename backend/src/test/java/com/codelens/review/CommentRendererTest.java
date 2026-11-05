package com.codelens.review;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.codelens.analysis.Finding;

class CommentRendererTest {

    private static Review review(int files) {
        Review r = new Review();
        r.repo = "acme/shop";
        r.headSha = "abc123";
        r.filesAnalyzed = files;
        return r;
    }

    private static FindingRecord finding(String file, String fix) {
        FindingRecord f = new FindingRecord();
        f.ruleId = "SQL_INJECTION";
        f.category = Finding.Category.SECURITY;
        f.severity = Finding.Severity.HIGH;
        f.file = file;
        f.line = 3;
        f.message = "SQL built from a value";
        f.explanation = "Explained";
        f.suggestedFix = fix;
        return f;
    }

    @Test
    void countsFilesWithoutAssumingJava() {
        String md = CommentRenderer.render(review(1), "https://github.com");
        assertTrue(md.contains("(1 file analysed)"), md);
        assertFalse(md.contains("Java"), md);
    }

    @Test
    void fencesTheSuggestedFixInTheFilesLanguage() {
        Review r = review(2);
        r.findings.add(finding("app/db.py", "cur.execute(q, (name,))"));
        r.findings.add(finding("src/A.java", "ps.setString(1, name);"));
        String md = CommentRenderer.render(r, "https://github.com");
        assertTrue(md.contains("```python\ncur.execute(q, (name,))\n```"), md);
        assertTrue(md.contains("```java\nps.setString(1, name);\n```"), md);
        assertTrue(md.contains("(2 files analysed)"), md);
    }

    @Test
    void saysSoWhenOtherLanguagesWentUnchecked() {
        Review r = review(3);
        r.semgrepMissing = true;
        String md = CommentRenderer.render(r, "https://github.com");
        assertTrue(md.contains("Semgrep is not installed"), md);
        assertFalse(CommentRenderer.render(review(3), "https://github.com").contains("Semgrep is not installed"));
    }

    @Test
    void fenceTagIsEmptyForUnknownOrPlainFiles() {
        assertEquals("", CommentRenderer.fence("Makefile.unknownext"));
        assertEquals("", CommentRenderer.fence(".env"));
        assertEquals("go", CommentRenderer.fence("cmd/main.go"));
    }
}
