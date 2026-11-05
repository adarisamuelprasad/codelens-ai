package com.codelens.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

class LanguagesTest {

    @Test
    void namesTheLanguageOfCommonFiles() {
        assertEquals("java", Languages.of("src/main/java/a/A.java"));
        assertEquals("python", Languages.of("app/views.py"));
        assertEquals("typescript", Languages.of("web/src/Page.tsx"));
        assertEquals("javascript", Languages.of("server.mjs"));
        assertEquals("go", Languages.of("cmd/api/main.go"));
        assertEquals("csharp", Languages.of("Api/UserController.cs"));
        assertEquals("cpp", Languages.of("src/engine.cpp"));
        assertEquals("dotenv", Languages.of(".env"));
        assertEquals("dotenv", Languages.of("deploy/.env.production"));
        assertEquals("dockerfile", Languages.of("Dockerfile"));
        assertEquals("yaml", Languages.of("src/main/resources/application.yml"));
        assertNull(Languages.of("logo.png"));
        assertNull(Languages.of("README"));
    }

    @Test
    void skipsGeneratedVendoredAndLockFiles() {
        assertTrue(Languages.reviewable("src/app.ts"));
        assertFalse(Languages.reviewable("node_modules/left-pad/index.js"));
        assertFalse(Languages.reviewable("web/dist/app.js"));
        assertFalse(Languages.reviewable("static/jquery.min.js"));
        assertFalse(Languages.reviewable("package-lock.json"));
        assertFalse(Languages.reviewable("go.sum"));
        assertFalse(Languages.reviewable("api/user.pb.go"));
        assertFalse(Languages.reviewable("vendor/github.com/x/y.go"));
        assertFalse(Languages.reviewable("docs/diagram.svg"));
    }

    @Test
    void recognisesTestFilesInEveryEcosystem() {
        for (String path : Set.of(
                "src/test/java/a/ATest.java", "src/main/java/a/AIT.java", "tests/test_api.py", "app/api_test.py",
                "conftest.py", "web/src/Page.test.tsx", "lib/util.spec.js", "web/__tests__/x.js",
                "pkg/store/store_test.go", "spec/models/user_spec.rb", "Api.Tests/UserTests.cs",
                "app/src/test/kotlin/RepoTest.kt")) {
            assertTrue(new ChangedFile(path, "added", "", Set.of()).isTest(), path);
        }
        for (String path : Set.of(
                "src/main/java/a/Latest.java", "src/main/java/a/Unit.java", "app/contest.py", "src/attest.go",
                "web/src/testimonials.tsx", "lib/specification.rb")) {
            assertFalse(new ChangedFile(path, "added", "", Set.of()).isTest(), path);
        }
    }
}
