package com.codelens.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.codelens.review.Review;
import com.codelens.review.ReviewService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * GitHub's pull_request webhook. The body is read as raw bytes because the
 * signature covers the exact bytes GitHub sent; parsing first and
 * re-serialising would change them.
 */
@RestController
public class WebhookController {

    static final Set<String> REVIEW_ACTIONS = Set.of("opened", "synchronize", "reopened", "ready_for_review");

    private final ReviewService reviews;
    private final ObjectMapper json;
    private final byte[] secret;

    public WebhookController(ReviewService reviews, ObjectMapper json,
                             @Value("${codelens.github.webhook-secret:}") String secret) {
        this.reviews = reviews;
        this.json = json;
        this.secret = secret == null ? new byte[0] : secret.getBytes(StandardCharsets.UTF_8);
    }

    @PostMapping("/api/github/webhook")
    public ResponseEntity<Map<String, Object>> receive(
            @RequestHeader(value = "X-Hub-Signature-256", required = false) String signature,
            @RequestHeader(value = "X-GitHub-Event", required = false) String event,
            @RequestBody byte[] body) throws Exception {
        if (secret.length == 0) {
            // Never accept unsigned deliveries: anyone could make the bot review anything.
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "not_configured", "Webhook secret is not set.");
        }
        if (!validSignature(secret, body, signature)) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "bad_signature", "Signature does not match.");
        }
        if ("ping".equals(event)) return ResponseEntity.ok(Map.of("status", "pong"));
        if (!"pull_request".equals(event)) return ResponseEntity.ok(Map.of("status", "ignored", "reason", "event"));

        JsonNode payload = json.readTree(body);
        String action = payload.path("action").asText();
        if (!REVIEW_ACTIONS.contains(action)) {
            return ResponseEntity.ok(Map.of("status", "ignored", "reason", "action " + action));
        }
        String repo = payload.path("repository").path("full_name").asText();
        int number = payload.path("pull_request").path("number").asInt();
        Long installation = payload.path("installation").path("id").isNumber()
            ? payload.path("installation").path("id").asLong() : null;
        Review r = reviews.enqueue(repo, number, Review.Trigger.WEBHOOK, installation);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("status", "queued", "reviewId", r.id));
    }

    static boolean validSignature(byte[] secret, byte[] body, String header) {
        if (header == null || !header.startsWith("sha256=")) return false;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] expected = mac.doFinal(body);
            byte[] given = HexFormat.of().parseHex(header.substring(7));
            return MessageDigest.isEqual(expected, given); // constant time
        } catch (IllegalArgumentException e) {
            return false; // not hex
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
