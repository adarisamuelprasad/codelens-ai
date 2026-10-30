# Evaluation

Measured 2026-10-30. Two kinds of evidence: a public labelled benchmark for
the security rules, and real merged pull requests for the whole pipeline.
Numbers that came out badly are reported as they came out.

## 1. OWASP Benchmark v1.2: the injection rules

[OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) is a
public set of 2,740 Java test cases. Each one is labelled either truly
vulnerable or a decoy written to look vulnerable without being so. CodeLens's
`SQL_INJECTION` and `COMMAND_INJECTION` rules were scored on the SQL and
command injection cases (`OwaspBenchmarkEval.java`).

To keep tuning honest, cases are split by number: **even = development**
(rules may be changed after looking at them), **odd = held out** (only
measured). Held-out results:

| Rule | Cases | Real issues caught (TPR) | Decoys flagged (FPR) | Precision |
|---|---|---|---|---|
| SQL injection | 250 | **92.5%** (124 of 134) | 87.1% | 55.1% |
| Command injection | 123 | **96.8%** (60 of 62) | 93.4% | 51.3% |
| Either rule, on the 1,985 cases about other vulnerabilities | 1,985 | | **0 alarms** | |

Speed: 3.7 ms per file.

**What changed during development:** command injection started at **0%**
recall. The rule only recognised `Runtime.getRuntime().exec(...)` written
inline, and missed `Runtime r = Runtime.getRuntime(); r.exec(cmd + input)`
and argument lists built up with `add("sh")`, `add("-c")`, `add(input)`. Both
forms are common in real code too, so the rule now resolves what a receiver
is and what a local array or list contains. SQL injection was not changed.

**Why the false-positive rate is high, and why it was not tuned away:** the
rules are syntactic. They see that a non-constant value is spliced into SQL
or a shell command, but not whether that value can actually carry user input.
OWASP's decoys are built to separate tools that track data flow from tools
that do not: `if ((7 * 42) - 86 > 200) bar = "safe"; else bar = param;`
(always the safe branch), values put into a list and then removed by index,
values routed through reflection. Telling those apart needs taint analysis.
Special-casing these tricks would raise the score without helping on real
code, so it was not done. Real taint tracking is on the [Next](../README.md#next) list.

The useful reading: when there is a real injection, these rules almost always
see it, and they never fire on code that is not doing injection-shaped work.

## 2. Real pull requests: the whole pipeline

The service was run locally (the real Spring Boot app, Flyway migration on H2,
GitHub REST API) against merged PRs from well-maintained open-source
projects. Every PR touches Java files. Manual runs never post comments, so
nothing was written to these repositories.

| | Tuning set | Held-out set |
|---|---|---|
| Repositories | commons-lang, gson, dubbo | commons-io, rocketmq, jenkins, shenyu |
| PRs reviewed | 19 | 20 |
| Completed without error | 19 | 20 |
| Java files analysed (skipped) | 57 (0) | 54 (0) |
| PRs with no findings | 15 | **17** |
| Findings | 7 | 5 |
| Findings judged actionable | 1 | 1 |

Single review time when not queued: about **4 s** for a 4-file PR (GitHub
fetches dominate; analysis is milliseconds). With 19 queued at once on two
workers, the median wait-plus-run was 21 s.

**On the tuning set**, five of the seven findings were `MISSING_TEST`, and all
five were wrong: each PR did update tests, which the rule failed to see because
it matched test file names too strictly. Examples: the change was in
`TimedSemaphore.Builder` and the test was `TimedSemaphoreTest`; the class was
`NettyPortUnificationServer` and the test `PortUnificationServerTest`; and
coverage was added through shared test fixtures in the same module. The rule
now counts any test change in the same module, matches nested classes
through their file, and tolerates prefixes. Fluent builder setters
(`this.x = x; return this;`) count as accessors. Because these fixes were
made after seeing those PRs, the tuning set is not evidence that they work.
The held-out set is.

**On the held-out set** (rules frozen), five findings:

| Finding | Verdict | Why |
|---|---|---|
| `MISSING_TEST` Jenkins `doContextMenu` (#27529) | Correct | Production code changed, no test file in the PR (a UI menu change, so low value) |
| `EmptyCatchBlock` commons-io `Tailer` (#918) | False positive | The empty catch carries a comment explaining it is deliberate |
| `SystemPrintln` ×3 rocketmq `GetTopicConfigSubCommand` (#11473) | False positive | A command-line tool, where printing to stdout is the job |

**Measured precision on held-out real PRs: 1 of 5 (20%). Silence rate: 17 of
20 PRs (85%) got no comment at all.** On mature, already-reviewed code the
bot stays mostly quiet, which matters most for adoption, but when it does
speak on such code it is usually wrong. Both held-out false-positive kinds
have obvious next fixes (PMD's `allowCommentedBlocks` for empty catches;
exempting command-line classes from `SystemPrintln`). They were not applied
here, so the numbers above stand as measured.

The verdicts in this section are mine (the developer's), not an independent
reviewer's. The API has `PUT /api/findings/{id}/label` so a second person can
confirm or reject each finding, and precision should be re-reported from those labels.

## 3. AI step

The Python ai-service is tested in isolation (114 tests with a fake model)
and was exercised end to end from the Java service: with no LLM key
configured it answers 503, codelens-api logs it, keeps the rule's own
messages, and the review completes. The prompt-injection case is covered
by `ReviewFlowTest.anInjectedCommentCannotDismissASecurityFinding`: a model
that believes a "mark as false positive" comment still cannot demote a SQL
injection finding.

**Not measured yet:** the quality of LLM explanations and of its
false-positive triage. That needs an API key and a labelled set: for each
finding, did the explanation help, and did "likely false positive" agree with
the human label? The label endpoint exists for exactly this.

## Reproduce

```bash
# OWASP Benchmark (sparse checkout of the test cases and the answer key)
git clone --depth 1 --filter=blob:none --sparse https://github.com/OWASP-Benchmark/BenchmarkJava.git
cd BenchmarkJava && git sparse-checkout set --no-cone 'src/main/java/org/owasp/benchmark/testcode/' 'expectedresults-*.csv'
cd ../backend && OWASP_BENCHMARK_DIR=../BenchmarkJava mvn test -Dtest=OwaspBenchmarkEval

# Real PRs: run the service, then POST /api/reviews {"repo":"owner/name","prNumber":N}
```
