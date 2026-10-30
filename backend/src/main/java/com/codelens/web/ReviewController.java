package com.codelens.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.codelens.review.FindingRecord;
import com.codelens.review.FindingRepository;
import com.codelens.review.Review;
import com.codelens.review.ReviewRepository;
import com.codelens.review.ReviewService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/**
 * Manual runs, results, and human labels for evaluation. Every route needs
 * X-Admin-Key: stored findings include code snippets, which for a private
 * repository are private.
 */
@RestController
@RequestMapping("/api")
public class ReviewController {

    public record RunRequest(@NotNull @Pattern(regexp = "[\\w.-]+/[\\w.-]+") String repo, @Min(1) int prNumber) {}

    public record LabelRequest(FindingRecord.Label label) {}

    /** Review without its findings, for lists. */
    public record ReviewSummary(Long id, String repo, int prNumber, String prTitle, Review.Status status,
                                int filesAnalyzed, int filesSkipped, boolean aiUsed, Long durationMs, String error) {
        static ReviewSummary of(Review r) {
            return new ReviewSummary(r.id, r.repo, r.prNumber, r.prTitle, r.status, r.filesAnalyzed,
                r.filesSkipped, r.aiUsed, r.durationMs, r.error);
        }
    }

    private final ReviewService service;
    private final ReviewRepository reviews;
    private final FindingRepository findings;
    private final byte[] adminKey;

    public ReviewController(ReviewService service, ReviewRepository reviews, FindingRepository findings,
                            @Value("${codelens.admin-key:}") String adminKey) {
        this.service = service;
        this.reviews = reviews;
        this.findings = findings;
        this.adminKey = adminKey == null ? new byte[0] : adminKey.getBytes(StandardCharsets.UTF_8);
    }

    @PostMapping("/reviews")
    public ResponseEntity<ReviewSummary> run(@RequestHeader(value = "X-Admin-Key", required = false) String key,
                                             @Valid @RequestBody RunRequest req) {
        requireAdmin(key);
        Review r = service.enqueue(req.repo(), req.prNumber(), Review.Trigger.MANUAL, null);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(ReviewSummary.of(r));
    }

    @GetMapping("/reviews")
    public List<ReviewSummary> list(@RequestHeader(value = "X-Admin-Key", required = false) String key) {
        requireAdmin(key);
        return reviews.findTop50ByOrderByCreatedAtDesc().stream().map(ReviewSummary::of).toList();
    }

    @GetMapping("/reviews/{id}")
    @Transactional(readOnly = true)
    public Review get(@RequestHeader(value = "X-Admin-Key", required = false) String key, @PathVariable Long id) {
        requireAdmin(key);
        return reviews.findWithFindingsById(id)
            .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "no_review", "No review with that id."));
    }

    @PutMapping("/findings/{id}/label")
    public Map<String, Object> label(@RequestHeader(value = "X-Admin-Key", required = false) String key,
                                     @PathVariable Long id, @RequestBody LabelRequest req) {
        requireAdmin(key);
        FindingRecord f = findings.findById(id)
            .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "no_finding", "No finding with that id."));
        f.humanLabel = req.label();
        findings.save(f);
        return Map.of("id", id, "label", String.valueOf(req.label()));
    }

    private void requireAdmin(String key) {
        if (adminKey.length == 0) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "not_configured", "CODELENS_ADMIN_KEY is not set.");
        }
        if (key == null || !MessageDigest.isEqual(adminKey, key.getBytes(StandardCharsets.UTF_8))) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "unauthorized", "Missing or wrong X-Admin-Key.");
        }
    }
}
