package com.codelens.github;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

/** The real client against a local stand-in for api.github.com, checking the exact paths it requests. */
class RestGitHubClientTest {

    private HttpServer server;
    private final List<String> paths = new CopyOnWriteArrayList<>();
    private final List<String> auth = new CopyOnWriteArrayList<>();
    private RestGitHubClient client;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            String path = ex.getRequestURI().getRawPath()
                + (ex.getRequestURI().getRawQuery() == null ? "" : "?" + ex.getRequestURI().getRawQuery());
            paths.add(path);
            auth.add(String.valueOf(ex.getRequestHeaders().getFirst("Authorization")));
            String body;
            int status = 200;
            if (path.endsWith("/pulls/7")) {
                body = "{\"title\":\"T\",\"html_url\":\"u\",\"head\":{\"sha\":\"abc\",\"repo\":{\"full_name\":\"fork/shop\"}}}";
            } else if (path.contains("/pulls/7/files")) {
                body = path.contains("page=1") ? "[{\"filename\":\"A.java\",\"status\":\"modified\",\"patch\":\"@@ -1 +1 @@\\n+x\"}]" : "[]";
            } else if (path.contains("/contents/")) {
                if (path.contains("Missing")) { status = 404; body = "{}"; } else body = "class A {}";
            } else {
                status = 404;
                body = "{}";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", path.contains("/contents/") ? "text/plain" : "application/json");
            ex.sendResponseHeaders(status, bytes.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(bytes);
            }
        });
        server.start();
        client = new RestGitHubClient("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    // Regression: "{repo}" with "acme/shop" was sent as acme%2Fshop and every call 404'd.
    @Test
    void ownerAndNameStayTwoPathSegments() {
        var pr = client.pull("acme/shop", 7, "tok");
        assertEquals("/repos/acme/shop/pulls/7", paths.get(0));
        assertEquals("abc", pr.headSha());
        assertEquals("fork/shop", pr.headRepo(), "fork PRs read files from the fork");
        assertEquals("Bearer tok", auth.get(0));
    }

    @Test
    void filesAreListedAndContentIsFetchedAtTheCommit() {
        var files = client.files("acme/shop", 7, null);
        assertEquals(1, files.size());
        assertEquals("/repos/acme/shop/pulls/7/files?per_page=100&page=1", paths.get(0));
        assertEquals("null", auth.get(0), "no token, no Authorization header");

        assertEquals("class A {}", client.content("fork/shop", "src/main/java/my dir/A.java", "abc", null));
        assertEquals("/repos/fork/shop/contents/src/main/java/my%20dir/A.java?ref=abc", paths.get(1));
        assertNull(client.content("fork/shop", "Missing.java", "abc", null));
    }
}
