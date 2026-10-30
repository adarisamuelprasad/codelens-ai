package com.codelens.github;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

@Component
public class RestGitHubClient implements GitHubClient {

    private static final int PAGE = 100;
    private static final int MAX_PAGES = 30; // GitHub lists at most 3,000 files per PR
    private static final ParameterizedTypeReference<List<Map<String, Object>>> LIST = new ParameterizedTypeReference<>() {};
    private static final ParameterizedTypeReference<Map<String, Object>> OBJECT = new ParameterizedTypeReference<>() {};

    private final String baseUrl;
    private final RestClient http;

    public RestGitHubClient(@Value("${codelens.github.api-url:https://api.github.com}") String apiUrl) {
        this.baseUrl = apiUrl;
        this.http = RestClient.builder().baseUrl(apiUrl)
            .defaultHeader("Accept", "application/vnd.github+json")
            .defaultHeader("X-GitHub-Api-Version", "2022-11-28")
            .defaultHeader("User-Agent", "codelens-ai")
            .build();
    }

    /**
     * URI variables for a repo plus extras. Owner and name are separate
     * variables because a template encodes "/" inside a single variable, which
     * turns owner/name into owner%2Fname and every call into a 404.
     */
    private static Map<String, Object> vars(String repo, Object... kv) {
        int slash = repo.indexOf('/');
        Map<String, Object> m = new java.util.HashMap<>();
        m.put("owner", repo.substring(0, slash));
        m.put("name", repo.substring(slash + 1));
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** Anonymous when there is no token: public repositories only, 60 requests an hour. */
    private RestClient as(String token) {
        return token == null || token.isBlank() ? http
            : http.mutate().defaultHeader("Authorization", "Bearer " + token).build();
    }

    @Override
    public PullRequest pull(String repo, int number, String token) {
        Map<String, Object> pr;
        try {
            pr = as(token).get().uri("/repos/{owner}/{name}/pulls/{n}", vars(repo, "n", number)).retrieve().body(OBJECT);
        } catch (HttpClientErrorException.NotFound e) {
            throw new IllegalArgumentException("Pull request " + repo + "#" + number + " not found (or not visible to this token).");
        }
        Map<?, ?> head = (Map<?, ?>) pr.get("head");
        Map<?, ?> headRepo = (Map<?, ?>) head.get("repo");
        return new PullRequest(repo, number, (String) pr.get("title"), (String) head.get("sha"),
            headRepo != null ? (String) headRepo.get("full_name") : repo, (String) pr.get("html_url"));
    }

    @Override
    public List<PrFile> files(String repo, int number, String token) {
        List<PrFile> out = new ArrayList<>();
        for (int page = 1; page <= MAX_PAGES; page++) {
            List<Map<String, Object>> batch = as(token).get()
                .uri("/repos/{owner}/{name}/pulls/{n}/files?per_page={pp}&page={p}",
                    vars(repo, "n", number, "pp", PAGE, "p", page))
                .retrieve().body(LIST);
            if (batch == null || batch.isEmpty()) break;
            for (Map<String, Object> f : batch) {
                out.add(new PrFile((String) f.get("filename"), (String) f.get("status"), (String) f.get("patch")));
            }
            if (batch.size() < PAGE) break;
        }
        return out;
    }

    @Override
    public String content(String repo, String path, String ref, String token) {
        // Built by hand: each path segment is encoded on its own, and a URI
        // template would encode the slashes between them.
        String encodedPath = String.join("/", Arrays.stream(path.split("/"))
            .map(s -> URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20")).toList());
        URI uri = URI.create(baseUrl + "/repos/" + repo + "/contents/" + encodedPath
            + "?ref=" + URLEncoder.encode(ref, StandardCharsets.UTF_8));
        try {
            return as(token).get().uri(uri).header("Accept", "application/vnd.github.raw").retrieve().body(String.class);
        } catch (HttpClientErrorException.NotFound e) {
            return null;
        }
    }

    @Override
    public void upsertComment(String repo, int number, String marker, String body, String token) {
        RestClient client = as(token);
        Long existing = null;
        for (int page = 1; page <= 10 && existing == null; page++) {
            List<Map<String, Object>> comments = client.get()
                .uri("/repos/{owner}/{name}/issues/{n}/comments?per_page=100&page={p}", vars(repo, "n", number, "p", page))
                .retrieve().body(LIST);
            if (comments == null || comments.isEmpty()) break;
            for (Map<String, Object> c : comments) {
                if (c.get("body") instanceof String b && b.contains(marker)) existing = ((Number) c.get("id")).longValue();
            }
        }
        if (existing != null) {
            client.patch().uri("/repos/{owner}/{name}/issues/comments/{id}", vars(repo, "id", existing))
                .contentType(MediaType.APPLICATION_JSON).body(Map.of("body", body)).retrieve().toBodilessEntity();
        } else {
            client.post().uri("/repos/{owner}/{name}/issues/{n}/comments", vars(repo, "n", number))
                .contentType(MediaType.APPLICATION_JSON).body(Map.of("body", body)).retrieve().toBodilessEntity();
        }
    }
}
