package com.codelens.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.codelens.diff.ChangedFile;

class PipelineTest {

    private final AnalysisPipeline pipeline = new AnalysisPipeline(new PmdAnalyzer(), new JavaRules(), new MissingTestRule(), 50);

    private static List<String> ids(List<Finding> f) {
        return f.stream().map(Finding::ruleId).toList();
    }

    @Test
    void pmdRulesetLoadsAndFindsRealBugs() {
        String src = """
            class A {
              boolean same(String a, String b) { return a == b; }
              void read() {
                try { java.io.FileInputStream in = new java.io.FileInputStream("x"); in.read(); }
                catch (java.io.IOException e) { }
              }
            }
            """;
        List<Finding> found = new PmdAnalyzer().analyze(List.of(JavaRulesTest.file("src/main/java/A.java", src)));
        assertTrue(ids(found).contains("UseEqualsToCompareStrings"), ids(found).toString());
        assertTrue(ids(found).contains("EmptyCatchBlock"), ids(found).toString());
        assertTrue(ids(found).contains("CloseResource"), ids(found).toString());
    }

    @Test
    void everyCatalogPmdRuleIsInTheRulesetAndViceVersa() throws Exception {
        String xml;
        try (InputStream in = getClass().getResourceAsStream("/rulesets/codelens.xml")) {
            xml = new String(in.readAllBytes());
        }
        Set<String> inXml = new HashSet<>();
        var m = java.util.regex.Pattern.compile("\\.xml/(\\w+)\"").matcher(xml);
        while (m.find()) inXml.add(m.group(1));
        assertEquals(RuleCatalog.PMD.keySet(), inXml);
    }

    @Test
    void onlyLinesThePrAddedAreReported() {
        String src = "class A {\n  void m(java.sql.Statement st, String id) throws Exception {\n"
            + "    st.executeQuery(\"SELECT * FROM a WHERE id = \" + id);\n"
            + "    st.executeQuery(\"SELECT * FROM b WHERE id = \" + id);\n  }\n}\n";
        ChangedFile f = new ChangedFile("src/main/java/A.java", "modified", src, Set.of(4));
        List<Finding> out = pipeline.analyze(List.of(f));
        assertEquals(1, out.size());
        assertEquals(4, out.get(0).line());
    }

    @Test
    void testFilesReportOnlySecurityAndBugs() {
        String src = "class ATest {\n  void t() { int unused = 1; System.out.println(\"x\"); }\n"
            + "  boolean b(String x) { return x == \"y\"; }\n}\n";
        List<Finding> out = pipeline.analyze(List.of(JavaRulesTest.file("src/test/java/ATest.java", src)));
        assertEquals(List.of("UseEqualsToCompareStrings"), ids(out));
    }

    @Test
    void swallowedExceptionSupersedesPrintStackTrace() {
        String src = "class A {\n  void m() {\n    try { m(); }\n    catch (RuntimeException e) {\n"
            + "      e.printStackTrace();\n    }\n  }\n}\n";
        List<String> out = ids(pipeline.analyze(List.of(JavaRulesTest.file("src/main/java/A.java", src))));
        assertTrue(out.contains("SWALLOWED_EXCEPTION"), out.toString());
        assertFalse(out.contains("AvoidPrintStackTrace"), out.toString());
    }

    @Test
    void sortedBySeverityAndCapped() {
        StringBuilder src = new StringBuilder("class A {\n  void m(java.sql.Statement st, String id) throws Exception {\n");
        // Not named "unused...": PMD deliberately skips locals with that prefix.
        for (int i = 0; i < 10; i++) src.append("    int count").append(i).append(" = ").append(i).append(";\n");
        src.append("    st.executeQuery(\"SELECT * FROM t WHERE id = \" + id);\n  }\n}\n");
        List<Finding> out = new AnalysisPipeline(new PmdAnalyzer(), new JavaRules(), new MissingTestRule(), 5)
            .analyze(List.of(JavaRulesTest.file("src/main/java/A.java", src.toString())));
        assertEquals(5, out.size());
        assertEquals("SQL_INJECTION", out.get(0).ruleId());
    }

    @Test
    void missingTestFiresForChangedLogicWithoutATestAndNotWithOne() {
        String svc = "package a;\npublic class OrderService {\n  public int total(int a, int b) {\n"
            + "    int t = a + b;\n    return t;\n  }\n  public int getCount() { return 1; }\n}\n";
        ChangedFile main = JavaRulesTest.file("src/main/java/a/OrderService.java", svc);
        assertEquals(List.of("MISSING_TEST"), ids(pipeline.analyze(List.of(main))));

        ChangedFile test = JavaRulesTest.file("src/test/java/a/OrderServiceTest.java", "class OrderServiceTest {}");
        assertTrue(pipeline.analyze(List.of(main, test)).isEmpty());
    }

    // Regressions from real PRs (commons-lang #1840, dubbo #16562, dubbo #16560), all of
    // which did update tests and were flagged anyway.
    @Test
    void anyTestChangeInTheSameModuleCounts() {
        String svc = "public class RequestUtils {\n  public static String decodePath(String v) {\n"
            + "    String x = v.replace(\"+\", \"%2B\");\n    return x;\n  }\n}\n";
        var main = JavaRulesTest.file("rpc-triple/src/main/java/a/RequestUtils.java", svc);
        var fixture = JavaRulesTest.file("rpc-triple/src/test/java/a/service/DemoServiceImpl.java", "class DemoServiceImpl {}");
        var otherModule = JavaRulesTest.file("other/src/test/java/a/DemoServiceImpl.java", "class DemoServiceImpl {}");
        assertTrue(pipeline.analyze(List.of(main, fixture)).isEmpty());
        assertEquals(List.of("MISSING_TEST"), ids(pipeline.analyze(List.of(main, otherModule))));
    }

    @Test
    void nestedClassesAndPrefixedNamesMatchTheirTest() {
        String outer = "public class TimedSemaphore {\n  public static class Builder {\n"
            + "    public Builder fair(boolean f) {\n      int a = 1;\n      return this;\n    }\n  }\n}\n";
        var main = JavaRulesTest.file("TimedSemaphore.java", outer);
        var test = JavaRulesTest.file("TimedSemaphoreTest.java", "class TimedSemaphoreTest {}");
        assertFalse(ids(pipeline.analyze(List.of(main, test))).contains("MISSING_TEST"));

        String netty = "public class NettyPortUnificationServer {\n  public void open() {\n    int a = 1;\n    a++;\n  }\n}\n";
        var nettyMain = JavaRulesTest.file("NettyPortUnificationServer.java", netty);
        var nettyTest = JavaRulesTest.file("PortUnificationServerTest.java", "class PortUnificationServerTest {}");
        assertFalse(ids(pipeline.analyze(List.of(nettyMain, nettyTest))).contains("MISSING_TEST"));
    }

    @Test
    void fluentBuilderSettersAreAccessors() {
        String b = "public class Cfg {\n  private boolean fair;\n  public Cfg setFair(boolean fair) {\n"
            + "    this.fair = fair;\n    return this;\n  }\n}\n";
        assertFalse(ids(pipeline.analyze(List.of(JavaRulesTest.file("x/Cfg.java", b)))).contains("MISSING_TEST"));
    }

    @Test
    void missingTestIgnoresAccessorsAndConfiguration() {
        String dto = "public class A {\n  private int n;\n  public int getN() { return n; }\n  public void setN(int n) { this.n = n; }\n}\n";
        assertTrue(pipeline.analyze(List.of(JavaRulesTest.file("src/main/java/A.java", dto))).isEmpty());
        String cfg = "@Configuration\npublic class Cfg {\n  public String bean() {\n    String s = \"x\";\n    return s;\n  }\n}\n";
        assertTrue(pipeline.analyze(List.of(JavaRulesTest.file("src/main/java/Cfg.java", cfg))).isEmpty());
    }
}
