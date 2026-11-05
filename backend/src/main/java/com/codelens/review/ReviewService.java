package com.codelens.review;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Service;

import com.codelens.ai.AiExplainer;
import com.codelens.analysis.AnalysisPipeline;
import com.codelens.analysis.Finding;
import com.codelens.analysis.RuleCatalog;
import com.codelens.diff.ChangedFile;
import com.codelens.diff.DiffParser;
import com.codelens.diff.Languages;
import com.codelens.github.GitHubClient;
import com.codelens.github.GitHubClient.PrFile;
import com.codelens.github.GitHubClient.PullRequest;
import com.codelens.github.GitHubTokens;

@Service
public class ReviewService {

    private static final Logger log = LoggerFactory.getLogger(ReviewService.class);
    static final int SNIPPET_CONTEXT = 6;
    static final String SECURITY_KEPT_REASON = "Security findings are never auto-dismissed; review manually.";

    private final ReviewRepository reviews;
    private final GitHubClient github;
    private final GitHubTokens tokens;
    private final AnalysisPipeline pipeline;
    private final AiExplainer ai;
    private final TaskExecutor executor;
    private final Clock clock;
    private final int maxFiles;
    private final int maxFileBytes;
    private final int aiMaxFindings;
    private final boolean postComments;
    private final String htmlBase;

    public ReviewService(ReviewRepository reviews, GitHubClient github, GitHubTokens tokens, AnalysisPipeline pipeline,
                         AiExplainer ai, @Qualifier("reviewExecutor") TaskExecutor executor, Clock clock,
                         @Value("${codelens.analysis.max-files:100}") int maxFiles,
                         @Value("${codelens.analysis.max-file-bytes:300000}") int maxFileBytes,
                         @Value("${codelens.ai.max-findings:15}") int aiMaxFindings,
                         @Value("${codelens.github.post-comments:true}") boolean postComments,
                         @Value("${codelens.github.html-url:https://github.com}") String htmlBase) {
        this.reviews = reviews;
        this.github = github;
        this.tokens = tokens;
        this.pipeline = pipeline;
        this.ai = ai;
        this.executor = executor;
        this.clock = clock;
        this.maxFiles = maxFiles;
        this.maxFileBytes = maxFileBytes;
        this.aiMaxFindings = aiMaxFindings;
        this.postComments = postComments;
        this.htmlBase = htmlBase;
    }

    /** Records the review and runs it in the background; the webhook must answer GitHub within 10 s. */
    public Review enqueue(String repo, int prNumber, Review.Trigger trigger, Long installationId) {
        Review r = new Review();
        r.repo = repo;
        r.prNumber = prNumber;
        r.triggerSource = trigger;
        r.status = Review.Status.QUEUED;
        r.createdAt = clock.instant();
        Review saved = reviews.save(r);
        executor.execute(() -> run(saved.id, installationId));
        return saved;
    }

    void run(Long reviewId, Long installationId) {
        Review r = reviews.findWithFindingsById(reviewId).orElseThrow();
        r.status = Review.Status.RUNNING;
        r = reviews.save(r);
        try {
            String token = tokens.forInstallation(installationId);
            PullRequest pr = github.pull(r.repo, r.prNumber, token);
            r.prTitle = pr.title();
            r.headSha = pr.headSha();

            List<ChangedFile> files = fetchFiles(pr, token, r);
            List<Finding> findings = pipeline.analyze(files);
            r.semgrepMissing = pipeline.semgrepMissingFor(files);
            Map<String, ChangedFile> byPath = files.stream().collect(Collectors.toMap(ChangedFile::path, f -> f));
            List<FindingRecord> records = new ArrayList<>();
            for (Finding f : findings) records.add(toRecord(f, r, byPath.get(f.file())));

            r.aiUsed = explain(records, pr);
            r.findings.clear();
            r.findings.addAll(records);

            if (postComments && token != null && r.triggerSource == Review.Trigger.WEBHOOK) {
                github.upsertComment(r.repo, r.prNumber, CommentRenderer.MARKER, CommentRenderer.render(r, htmlBase), token);
                r.commentPosted = true;
            }
            r.status = Review.Status.DONE;
        } catch (Exception e) {
            log.warn("Review {} of {}#{} failed: {}", r.id, r.repo, r.prNumber, e.toString());
            r.status = Review.Status.FAILED;
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            r.error = msg.length() > 1900 ? msg.substring(0, 1900) : msg;
        } finally {
            r.finishedAt = clock.instant();
            r.durationMs = Duration.between(r.createdAt, r.finishedAt).toMillis();
            reviews.save(r);
        }
    }

    /** Every source or config file the PR added or changed, in any language CodeLens reads. */
    private List<ChangedFile> fetchFiles(PullRequest pr, String token, Review r) {
        List<ChangedFile> out = new ArrayList<>();
        for (PrFile f : github.files(pr.repo(), pr.number(), token)) {
            if (!Languages.reviewable(f.filename()) || "removed".equals(f.status())) continue;
            boolean added = "added".equals(f.status());
            if (out.size() >= maxFiles || (f.patch() == null && !added)) {
                r.filesSkipped++; // over the cap, or GitHub omitted the diff (too large)
                continue;
            }
            String content = github.content(pr.headRepo(), f.filename(), pr.headSha(), token);
            if (content == null || content.length() > maxFileBytes) {
                r.filesSkipped++;
                continue;
            }
            Set<Integer> lines = added
                ? IntStream.rangeClosed(1, content.split("\n", -1).length).boxed().collect(Collectors.toSet())
                : DiffParser.addedLines(f.patch());
            out.add(new ChangedFile(f.filename(), f.status(), content, lines));
        }
        r.filesAnalyzed = out.size();
        return out;
    }

    /**
     * Asks the AI about the most severe findings, then re-applies the security
     * rule here as well. True when at least one explanation came back.
     */
    private boolean explain(List<FindingRecord> records, PullRequest pr) {
        if (!ai.enabled() || records.isEmpty()) return false;
        List<AiExplainer.Item> items = new ArrayList<>();
        for (int i = 0; i < Math.min(aiMaxFindings, records.size()); i++) {
            FindingRecord f = records.get(i);
            RuleCatalog.Rule rule = RuleCatalog.get(f.ruleId);
            String language = Languages.of(f.file);
            items.add(new AiExplainer.Item("f" + i, f.ruleId, f.category.name().toLowerCase(Locale.ROOT),
                f.severity.name().toLowerCase(Locale.ROOT), f.message, rule == null ? "" : rule.description(),
                f.file, f.line, f.snippet == null ? "" : f.snippet, language == null ? "" : language));
        }
        Map<String, AiExplainer.Explanation> results = ai.explain(pr.repo(), pr.title(), items);
        for (int i = 0; i < items.size(); i++) {
            AiExplainer.Explanation e = results.get("f" + i);
            if (e == null) continue;
            FindingRecord f = records.get(i);
            f.explanation = e.explanation();
            f.suggestedFix = e.suggestedFix();
            f.aiVerdict = e.verdict();
            f.aiVerdictReason = e.verdictReason();
            // The PR author wrote the code the model read; a security finding is
            // never dismissed on the model's word.
            if (f.category == Finding.Category.SECURITY && f.demoted()) {
                f.aiVerdict = "true_positive";
                f.aiVerdictReason = SECURITY_KEPT_REASON;
            }
        }
        return !results.isEmpty();
    }

    private static FindingRecord toRecord(Finding f, Review r, ChangedFile file) {
        FindingRecord x = new FindingRecord();
        x.review = r;
        x.ruleId = f.ruleId();
        x.source = f.source();
        x.category = f.category();
        x.severity = f.severity();
        x.file = f.file();
        x.line = f.line();
        x.message = f.message().length() > 1900 ? f.message().substring(0, 1900) : f.message();
        x.snippet = file == null ? null : snippet(file.content(), f.line());
        return x;
    }

    /** Numbered lines around the finding, e.g. "41 | ...", capped for storage. */
    static String snippet(String content, int line) {
        String[] lines = content.split("\n", -1);
        int from = Math.max(1, line - SNIPPET_CONTEXT);
        int to = Math.min(lines.length, line + SNIPPET_CONTEXT);
        StringBuilder sb = new StringBuilder();
        for (int i = from; i <= to; i++) sb.append(i).append(" | ").append(lines[i - 1].replace("\r", "")).append('\n');
        return sb.length() > 7900 ? sb.substring(0, 7900) : sb.toString();
    }
}
