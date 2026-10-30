package com.codelens.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

class DiffParserTest {

    @Test
    void addedLinesAreCountedInTheNewFile() {
        String patch = """
            @@ -10,6 +10,8 @@ public class A {
               int a;
            -  int b;
            +  int b2;
            +  int c;
               int d;
            @@ -40,3 +42,4 @@ public class A {
               void m() {
            +    log();
               }
            """;
        assertEquals(Set.of(11, 12, 43), DiffParser.addedLines(patch));
    }

    @Test
    void removalsDoNotAdvanceTheNewLineCounter() {
        String patch = "@@ -1,4 +1,2 @@\n-a\n-b\n c\n+d\n";
        assertEquals(Set.of(2), DiffParser.addedLines(patch));
    }

    @Test
    void newFileHunkWithoutCounts() {
        assertEquals(Set.of(1), DiffParser.addedLines("@@ -0,0 +1 @@\n+only line\n"));
    }

    @Test
    void noNewlineMarkerIsIgnored() {
        String patch = "@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b\n\\ No newline at end of file\n";
        assertEquals(Set.of(2), DiffParser.addedLines(patch));
    }

    @Test
    void blankContextLineWithItsSpaceStrippedStillCounts() {
        String patch = "@@ -1,3 +1,4 @@\n a\n\n+c\n d\n";
        assertEquals(Set.of(3), DiffParser.addedLines(patch));
    }

    @Test
    void nullOrEmptyPatchHasNoLines() {
        assertTrue(DiffParser.addedLines(null).isEmpty());
        assertTrue(DiffParser.addedLines("").isEmpty());
    }
}
