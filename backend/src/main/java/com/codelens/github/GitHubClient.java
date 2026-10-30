package com.codelens.github;

import java.util.List;

/** The handful of GitHub REST calls a review needs. {@code token} may be null (anonymous, public repos only). */
public interface GitHubClient {

    record PullRequest(String repo, int number, String title, String headSha, String headRepo, String htmlUrl) {}

    /** One file of a PR. {@code patch} is null when GitHub omits it (binary or very large diffs). */
    record PrFile(String filename, String status, String patch) {}

    PullRequest pull(String repo, int number, String token);

    List<PrFile> files(String repo, int number, String token);

    /** Raw file content at a commit, or null if it does not exist there. */
    String content(String repo, String path, String ref, String token);

    /** Creates the review comment, or edits the one already carrying {@code marker}. */
    void upsertComment(String repo, int number, String marker, String body, String token);
}
