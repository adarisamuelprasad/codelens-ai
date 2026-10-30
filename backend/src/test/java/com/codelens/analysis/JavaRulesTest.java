package com.codelens.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import com.codelens.diff.ChangedFile;

class JavaRulesTest {

    private final JavaRules rules = new JavaRules();

    // Built at runtime so no AWS-shaped literal sits in the repository for secret scanners to trip on.
    private static final String FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP";

    static ChangedFile file(String path, String body) {
        Set<Integer> all = IntStream.rangeClosed(1, body.split("\n").length).boxed().collect(Collectors.toSet());
        return new ChangedFile(path, "added", body, all);
    }

    private List<String> ruleIds(String body) {
        return rules.analyze(List.of(file("src/main/java/a/A.java", body))).stream().map(Finding::ruleId).toList();
    }

    private static String inMethod(String statements) {
        return "class A {\n  void m(String id, String name, java.sql.Connection conn, java.sql.Statement st,"
            + " org.springframework.jdbc.core.JdbcTemplate jdbc) throws Exception {\n" + statements + "\n  }\n}\n";
    }

    // ---- SQL injection

    @Test
    void sqlConcatenatedIntoExecuteQuery() {
        assertEquals(List.of("SQL_INJECTION"), ruleIds(inMethod("st.executeQuery(\"SELECT * FROM users WHERE id = \" + id);")));
    }

    @Test
    void sqlBuiltInAVariableFirst() {
        assertTrue(ruleIds(inMethod("String q = \"DELETE FROM t WHERE name = '\" + name + \"'\";\n jdbc.update(q);"))
            .contains("SQL_INJECTION"));
    }

    @Test
    void sqlAppendedWithPlusEquals() {
        assertTrue(ruleIds(inMethod("String q = \"SELECT * FROM t WHERE 1=1\";\n q += \" AND name = \" + name;\n st.executeQuery(q);"))
            .contains("SQL_INJECTION"));
    }

    @Test
    void sqlViaStringFormatAndStringBuilder() {
        assertTrue(ruleIds(inMethod("jdbc.queryForList(String.format(\"SELECT * FROM t WHERE id = %s\", id));"))
            .contains("SQL_INJECTION"));
        assertTrue(ruleIds(inMethod("StringBuilder sb = new StringBuilder(\"SELECT * FROM t WHERE id = \");\n"
            + " sb.append(id);\n st.executeQuery(sb.toString());")).contains("SQL_INJECTION"));
    }

    @Test
    void boundParametersAndConstantsAreFine() {
        assertTrue(ruleIds(inMethod("conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");")).isEmpty());
        assertTrue(ruleIds(inMethod("jdbc.query(\"SELECT * FROM t WHERE \" + COLUMN + \" = ?\", r -> 1, id);")).isEmpty());
        assertTrue(ruleIds(inMethod("jdbc.update(\"UPDATE t SET a = ? WHERE id = ?\", name, id);")).isEmpty());
        // Concatenation that is not SQL at all, passed to an "execute" method.
        assertTrue(ruleIds(inMethod("executor.execute(\"task-\" + id);")).isEmpty());
    }

    // ---- Command injection

    @Test
    void runtimeExecWithAVariable() {
        assertTrue(ruleIds(inMethod("Runtime.getRuntime().exec(\"ping \" + name);")).contains("COMMAND_INJECTION"));
        assertTrue(ruleIds(inMethod("Runtime.getRuntime().exec(new String[]{\"ls\", \"-l\"});")).isEmpty());
    }

    @Test
    void processBuilderThroughAShell() {
        assertTrue(ruleIds(inMethod("new ProcessBuilder(\"sh\", \"-c\", name).start();")).contains("COMMAND_INJECTION"));
        assertTrue(ruleIds(inMethod("new ProcessBuilder(\"git\", \"status\").start();")).isEmpty());
    }

    @Test
    void runtimeHeldInAVariable() {
        assertTrue(ruleIds(inMethod("Runtime r = Runtime.getRuntime();\n r.exec(\"ping \" + name);")).contains("COMMAND_INJECTION"));
        assertTrue(ruleIds(inMethod("Runtime r = Runtime.getRuntime();\n String[] cmd = {\"ls\", \"-l\"};\n r.exec(cmd);")).isEmpty());
    }

    @Test
    void shellArgumentListBuiltUpWithAdd() {
        String body = "java.util.List<String> args = new java.util.ArrayList<>();\n args.add(\"sh\");\n args.add(\"-c\");\n"
            + " args.add(\"echo \" + name);\n ProcessBuilder pb = new ProcessBuilder();\n pb.command(args);";
        assertTrue(ruleIds(inMethod(body)).contains("COMMAND_INJECTION"));
        // A program run directly with a user value as one argument is not a shell injection.
        String direct = "java.util.List<String> args = new java.util.ArrayList<>();\n args.add(\"git\");\n args.add(\"log\");\n"
            + " args.add(name);\n new ProcessBuilder(args).start();";
        assertTrue(ruleIds(inMethod(direct)).isEmpty());
    }

    @Test
    void windowsShellToo() {
        assertTrue(ruleIds(inMethod("new ProcessBuilder(\"cmd.exe\", \"/c\", name).start();")).contains("COMMAND_INJECTION"));
    }

    // ---- Secrets

    @Test
    void hardcodedPasswordAndApiKey() {
        assertTrue(ruleIds("class A { private static final String DB_PASSWORD = \"admin@123\"; }").contains("HARDCODED_SECRET"));
        assertTrue(ruleIds("class A { String apiKey = \"9f8e7d6c5b4a39281706\"; }").contains("HARDCODED_SECRET"));
    }

    @Test
    void secretShapedNamesHoldingNonSecretsAreFine() {
        assertTrue(ruleIds("class A { static final String TOKEN_HEADER = \"Authorization\"; }").isEmpty());
        assertTrue(ruleIds("class A { static final String PASSWORD_PARAM = \"pwd_field_1\"; }").isEmpty());
        assertTrue(ruleIds("class A { String password = \"${DB_PASSWORD}\"; }").isEmpty());
        assertTrue(ruleIds("class A { String secret = \"changeme\"; }").isEmpty());
        assertTrue(ruleIds("class A { String token = \"short\"; }").isEmpty());
    }

    @Test
    void knownTokenFormatsAreFlaggedWhateverTheName() {
        String ghp = "ghp_" + "a".repeat(36);
        assertEquals(List.of("HARDCODED_SECRET"), ruleIds("class A { String x = \"" + ghp + "\"; }"));
        assertEquals(List.of("HARDCODED_SECRET"), ruleIds("class A { String k = \"" + FAKE_AWS + "\"; }"));
    }

    @Test
    void secretNamedVariablesInTestsAreSkippedButRealTokensAreNot() {
        var testFile = file("src/test/java/a/ATest.java", "class ATest { String password = \"admin@123\"; }");
        assertTrue(rules.analyze(List.of(testFile)).isEmpty());
        var leaked = file("src/test/java/a/ATest.java", "class ATest { String k = \"" + FAKE_AWS + "\"; }");
        assertEquals(1, rules.analyze(List.of(leaked)).size());
    }

    // ---- Web security

    @Test
    void openCors() {
        assertTrue(ruleIds("@CrossOrigin class A {}").contains("PERMISSIVE_CORS"));
        assertTrue(ruleIds("@CrossOrigin(\"*\") class A {}").contains("PERMISSIVE_CORS"));
        assertTrue(ruleIds("@CrossOrigin(origins = \"*\", maxAge = 3600) class A {}").contains("PERMISSIVE_CORS"));
        assertTrue(ruleIds("@CrossOrigin(maxAge = 3600) class A {}").contains("PERMISSIVE_CORS"));
        assertTrue(ruleIds(inMethod("registry.addMapping(\"/**\").allowedOrigins(\"*\");")).contains("PERMISSIVE_CORS"));
    }

    @Test
    void restrictedCorsIsFine() {
        assertTrue(ruleIds("@CrossOrigin(origins = \"https://app.example.com\") class A {}").isEmpty());
        assertTrue(ruleIds(inMethod("registry.addMapping(\"/**\").allowedOrigins(\"https://app.example.com\");")).isEmpty());
    }

    @Test
    void csrfDisabledInAllThreeStyles() {
        assertTrue(ruleIds(inMethod("http.csrf().disable();")).contains("CSRF_DISABLED"));
        assertTrue(ruleIds(inMethod("http.csrf(c -> c.disable());")).contains("CSRF_DISABLED"));
        assertTrue(ruleIds(inMethod("http.csrf(AbstractHttpConfigurer::disable);")).contains("CSRF_DISABLED"));
        assertTrue(ruleIds(inMethod("http.csrf(c -> c.ignoringRequestMatchers(\"/webhook\"));")).isEmpty());
    }

    // ---- Spring and exceptions

    @Test
    void transactionalOnPrivateOrFinalMethod() {
        assertTrue(ruleIds("class A { @Transactional private void save() {} }").contains("PROXY_ANNOTATION_ON_PRIVATE"));
        assertTrue(ruleIds("class A { @Async public final void run() {} }").contains("PROXY_ANNOTATION_ON_PRIVATE"));
        assertTrue(ruleIds("class A { @Transactional public void save() {} }").isEmpty());
    }

    @Test
    void catchThatOnlyPrints() {
        assertTrue(ruleIds(inMethod("try { m(); } catch (Exception e) { e.printStackTrace(); }")).contains("SWALLOWED_EXCEPTION"));
        assertTrue(ruleIds(inMethod("try { m(); } catch (Exception e) { System.out.println(e); }")).contains("SWALLOWED_EXCEPTION"));
        assertFalse(ruleIds(inMethod("try { m(); } catch (Exception e) { e.printStackTrace(); throw e; }")).contains("SWALLOWED_EXCEPTION"));
    }

    @Test
    void unparseableFilesAreSkippedNotFatal() {
        assertTrue(ruleIds("class A { void m( { }").isEmpty());
    }

    @Test
    void findingsCarryTheRightLine() {
        List<Finding> f = rules.analyze(List.of(file("src/main/java/a/A.java",
            "class A {\n  void m(java.sql.Statement st, String id) throws Exception {\n    int x = 1;\n"
            + "    st.executeQuery(\"SELECT * FROM t WHERE id = \" + id);\n  }\n}\n")));
        assertEquals(4, f.get(0).line());
    }
}
