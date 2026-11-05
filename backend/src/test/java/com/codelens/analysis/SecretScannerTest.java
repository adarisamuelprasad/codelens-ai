package com.codelens.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.codelens.diff.ChangedFile;

class SecretScannerTest {

    private final SecretScanner scanner = new SecretScanner();

    private List<Integer> lines(String path, String body) {
        return scanner.analyze(List.of(JavaRulesTest.file(path, body))).stream().map(Finding::line).toList();
    }

    @Test
    void findsNamedSecretsInSourceOfAnyLanguage() {
        assertEquals(List.of(1), lines("app/config.py", "DB_PASSWORD = \"pr0d-S3cret-99\"\n"));
        assertEquals(List.of(1), lines("src/db.ts", "const apiKey = 'a8f5f167f44f4964e6c998dee827110c';\n"));
        assertEquals(List.of(1), lines("main.go", "\tpassword := \"hunter2-but-longer\"\n"));
        assertEquals(List.of(1), lines("config/app.rb", "  secret_token => 'b1946ac92492d2347c6235b4d2611184'\n"));
    }

    @Test
    void findsSecretsInConfigFilesWrittenBare() {
        assertEquals(List.of(2), lines(".env", "PORT=8080\nSTRIPE_SECRET=sk_live_abcdefgh12345678\n"));
        assertEquals(List.of(1), lines("src/main/resources/application.properties",
            "spring.datasource.password=Sup3rS3cret!\n"));
        assertEquals(List.of(2), lines("deploy/values.yaml", "db:\n  password: Sup3rS3cret99\n"));
    }

    @Test
    void findsKnownTokenFormatsWhateverTheName() {
        assertEquals(List.of(1), lines("scripts/deploy.sh",
            "curl -H \"Authorization: token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" https://api.github.com\n"));
        // A real token in a test is still a leaked token.
        assertEquals(List.of(1), lines("tests/test_api.py", "KEY = 'AKIAABCDEFGHIJKLMNOP'\n"));
    }

    @Test
    void leavesReferencesPlaceholdersAndLabelsAlone() {
        String body = String.join("\n",
            "DB_PASSWORD = os.environ[\"DB_PASSWORD\"]",
            "password: ${DB_PASSWORD}",
            "API_KEY=$API_KEY",
            "token = process.env.TOKEN",
            "PASSWORD_FIELD = \"password-input-1\"",
            "secret = \"changeme\"",
            "\"passwordLabel\": \"Enter your password\",",
            "password = \"short\"",
            "");
        assertEquals(List.of(), lines("app/settings.py", body));
        assertEquals(List.of(), lines("config/.env", "API_KEY=$API_KEY\nDB_PASSWORD=${DB_PASSWORD}\n"));
    }

    @Test
    void ignoresNamedSecretsInTestsAndExampleFiles() {
        assertEquals(List.of(), lines("tests/test_login.py", "password = \"Correct-Horse-9\"\n"));
        assertEquals(List.of(), lines(".env.example", "DB_PASSWORD=Sup3rS3cret99\n"));
    }

    @Test
    void onlyReportsLinesThePrChanged() {
        ChangedFile f = new ChangedFile("app/config.py", "modified",
            "DB_PASSWORD = \"pr0d-S3cret-99\"\nOTHER = 1\n", Set.of(2));
        assertEquals(List.of(), scanner.analyze(List.of(f)));
    }

    @Test
    void leavesJavaToTheAstRules() {
        assertEquals(List.of(), lines("src/main/java/a/A.java", "class A { String password = \"pr0d-S3cret-99\"; }\n"));
    }

    @Test
    void namedSecretNeedsASecretNameAndASecretLookingValue() {
        assertEquals("api-key", SecretScanner.namedSecret("api-key: Zx81aQ0pLm22", true));
        assertNull(SecretScanner.namedSecret("username: admin12345", true));
        assertNull(SecretScanner.namedSecret("token_ttl = \"3600s-or-more\"", false));
    }
}
