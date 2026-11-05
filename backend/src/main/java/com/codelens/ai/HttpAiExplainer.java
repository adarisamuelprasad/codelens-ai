package com.codelens.ai;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

// Any failure (not configured, timeout, 503, malformed reply) returns an empty
// map and the review completes without AI text. AI is an enhancement here,
// never a dependency.
@Component
public class HttpAiExplainer implements AiExplainer {

    private static final Logger log = LoggerFactory.getLogger(HttpAiExplainer.class);

    private final String key;
    private final RestClient client;

    public HttpAiExplainer(@Value("${codelens.ai.url:}") String url,
                           @Value("${codelens.ai.key:}") String key,
                           @Value("${codelens.ai.timeout-seconds:90}") int timeoutSeconds) {
        this.key = key;
        if (url == null || url.isBlank() || key == null || key.isBlank()) {
            this.client = null;
            return;
        }
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build());
        factory.setReadTimeout(Duration.ofSeconds(timeoutSeconds));
        this.client = RestClient.builder().baseUrl(url).requestFactory(factory).build();
    }

    @Override
    public boolean enabled() {
        return client != null;
    }

    @Override
    public Map<String, Explanation> explain(String repo, String prTitle, List<Item> items) {
        if (client == null || items.isEmpty()) return Map.of();
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("repo", repo);
        context.put("prTitle", prTitle == null ? "" : prTitle);
        try {
            Map<?, ?> body = client.post().uri("/v1/explain")
                .header("X-CodeLens-Key", key)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("context", context, "findings", items.stream().map(HttpAiExplainer::toJson).toList()))
                .retrieve().body(Map.class);
            Map<String, Explanation> out = new HashMap<>();
            if (body != null && body.get("results") instanceof List<?> results) {
                for (Object o : results) {
                    if (o instanceof Map<?, ?> r && r.get("id") instanceof String id) {
                        out.put(id, new Explanation(str(r.get("explanation")), str(r.get("suggestedFix")),
                            str(r.get("verdict")), str(r.get("verdictReason"))));
                    }
                }
            }
            return out;
        } catch (RestClientResponseException e) {
            log.info("ai-service answered {}; storing findings without AI text", e.getStatusCode().value());
        } catch (Exception e) {
            log.warn("ai-service unreachable ({}); storing findings without AI text", e.getMessage());
        }
        return Map.of();
    }

    private static Map<String, Object> toJson(Item i) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", i.id());
        m.put("ruleId", i.ruleId());
        m.put("category", i.category());
        m.put("severity", i.severity());
        m.put("message", i.message());
        m.put("ruleDescription", i.ruleDescription());
        m.put("file", i.file());
        m.put("line", i.line());
        m.put("snippet", i.snippet());
        if (i.language() != null && !i.language().isEmpty()) m.put("language", i.language());
        return m;
    }

    private static String str(Object o) {
        return o instanceof String s ? s : null;
    }
}
