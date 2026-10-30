package com.codelens.diff;

import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the unified diff GitHub returns per file (the {@code patch} field of
 * GET /pulls/{n}/files) and answers one question: which line numbers in the
 * NEW version of the file did this PR add or change?
 */
public final class DiffParser {

    private static final Pattern HUNK = Pattern.compile("^@@ -\\d+(?:,\\d+)? \\+(\\d+)(?:,\\d+)? @@");

    private DiffParser() {}

    public static Set<Integer> addedLines(String patch) {
        Set<Integer> added = new TreeSet<>();
        if (patch == null) return added;
        int line = -1;
        String[] lines = patch.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String l = lines[i];
            Matcher m = HUNK.matcher(l);
            if (m.find()) {
                line = Integer.parseInt(m.group(1));
                continue;
            }
            if (line < 0) continue;                    // before the first hunk
            if (l.isEmpty()) {
                // A blank context line whose leading space was stripped by
                // something along the way; the final empty piece is just the
                // split after the last newline.
                if (i < lines.length - 1) line++;
                continue;
            }
            switch (l.charAt(0)) {
                case '+' -> added.add(line++);
                case ' ' -> line++;
                case '-', '\\' -> { }                  // removed line, or "\ No newline at end of file"
                default -> line++;                     // defensive: treat unknown as context
            }
        }
        return added;
    }
}
