package com.codelens.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.codelens.diff.ChangedFile;
import com.codelens.diff.Languages;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Runs CodeLens's Semgrep rule pack (semgrep/codelens-rules.yml) over the
 * PR's non-Java files: Python, JavaScript/TypeScript, Go, C#, PHP, Ruby,
 * Kotlin and C/C++.
 *
 * Semgrep is a separate program (the Docker image installs it). Everything it
 * needs is local: our rules, files written to a temp folder, metrics off, no
 * registry, no login, so no PR code leaves the machine. When it is missing or
 * fails, the review still runs with the other analyzers and this one reports
 * nothing; {@link #available()} says which, and the PR comment says so.
 *
 * Each file is written as {@code <index>/<file name>}, not at its repo path:
 * Semgrep skips anything under test/ or tests/ by default and an empty
 * .semgrepignore does not turn that off, and a numbered folder also means a
 * hostile path from the PR can never point outside the temp folder.
 */
@Component
public class SemgrepAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(SemgrepAnalyzer.class);
    static final String RULES_RESOURCE = "semgrep/codelens-rules.yml";

    private final String command;
    private final int timeoutSeconds;
    private final ObjectMapper json = new ObjectMapper();
    private volatile Boolean available;

    public SemgrepAnalyzer(@Value("${codelens.semgrep.command:semgrep}") String command,
                           @Value("${codelens.semgrep.timeout-seconds:120}") int timeoutSeconds) {
        this.command = command;
        this.timeoutSeconds = timeoutSeconds;
    }

    /** True when Semgrep ran (or would run); false once it was found missing or broken. */
    public boolean available() {
        if (available == null) available = probe();
        return available;
    }

    public static boolean handles(ChangedFile f) {
        return Languages.SEMGREP.contains(f.language());
    }

    public List<Finding> analyze(List<ChangedFile> files) {
        List<ChangedFile> targets = files.stream().filter(SemgrepAnalyzer::handles).toList();
        if (targets.isEmpty() || command.isBlank() || !available()) return List.of();

        Path dir = null;
        try {
            dir = Files.createTempDirectory("codelens-semgrep-");
            Path rules = dir.resolve("rules.yml");
            try (InputStream in = getClass().getClassLoader().getResourceAsStream(RULES_RESOURCE)) {
                if (in == null) throw new IOException(RULES_RESOURCE + " is not on the classpath");
                Files.copy(in, rules);
            }
            Path src = dir.resolve("src");
            Map<String, ChangedFile> byRelative = new HashMap<>();
            for (int i = 0; i < targets.size(); i++) {
                ChangedFile f = targets.get(i);
                String name = f.path().substring(f.path().lastIndexOf('/') + 1);
                Path folder = Files.createDirectories(src.resolve(Integer.toString(i)));
                Path file = folder.resolve(name).normalize();
                if (!file.startsWith(folder)) continue; // a name like ".." cannot escape
                Files.writeString(file, f.content(), StandardCharsets.UTF_8);
                byRelative.put(i + "/" + name, f);
            }

            Path out = dir.resolve("out.json");
            Path err = dir.resolve("err.txt");
            Process p = new ProcessBuilder(command, "scan", "--config", rules.toString(), "--json",
                "--metrics=off", "--disable-version-check", "--quiet", "--no-git-ignore",
                "--timeout", "30", "--max-target-bytes", "1000000", src.toString())
                .directory(dir.toFile())
                .redirectOutput(out.toFile())
                .redirectError(err.toFile())
                .start();
            if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                log.warn("Semgrep took over {} s; non-Java rules skipped for this review", timeoutSeconds);
                return List.of();
            }
            // 0 = ran, findings or not. Other codes can still come with usable JSON
            // (one unparseable file); with none, it was a crash or a bad rule file.
            String output = Files.exists(out) ? Files.readString(out, StandardCharsets.UTF_8) : "";
            if (p.exitValue() != 0) log.warn("Semgrep exited {}: {}", p.exitValue(), tail(err));
            if (output.isBlank()) return List.of();
            return parse(output, src, byRelative);
        } catch (IOException e) {
            log.warn("Semgrep could not run ({}); non-Java rules skipped", e.getMessage());
            return List.of();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return List.of();
        } finally {
            if (dir != null) deleteQuietly(dir);
        }
    }

    List<Finding> parse(String output, Path src, Map<String, ChangedFile> byRelative) throws IOException {
        JsonNode root = json.readTree(output);
        for (JsonNode e : root.path("errors")) {
            // A file Semgrep could not parse is skipped, the rest still count.
            log.info("Semgrep: {} {}", e.path("type").asText(), e.path("message").asText().lines().findFirst().orElse(""));
        }
        List<Finding> out = new ArrayList<>();
        for (JsonNode r : root.path("results")) {
            String ruleId = r.path("extra").path("metadata").path("codelens_rule").asText("");
            RuleCatalog.Rule rule = RuleCatalog.CODELENS.get(ruleId);
            if (rule == null) continue; // RuleCatalogTest keeps this from happening
            // Semgrep reports the path as given (absolute here) or relative to its working folder.
            Path reported = src.getParent().resolve(r.path("path").asText()).normalize();
            if (!reported.startsWith(src)) continue;
            String relative = src.relativize(reported).toString().replace('\\', '/');
            ChangedFile f = byRelative.get(relative);
            if (f == null) continue;
            String message = r.path("extra").path("message").asText("").replaceAll("\\s+", " ").trim();
            out.add(new Finding(ruleId, "semgrep", rule.category(), rule.severity(), f.path(),
                r.path("start").path("line").asInt(1), message.isEmpty() ? rule.description() : message));
        }
        return out;
    }

    private boolean probe() {
        if (command.isBlank()) return false;
        try {
            Process p = new ProcessBuilder(command, "--version").redirectErrorStream(true).start();
            boolean done = p.waitFor(60, TimeUnit.SECONDS);
            if (done && p.exitValue() == 0) return true;
            if (!done) p.destroyForcibly();
            log.warn("'{} --version' failed; reviews will cover Java and secrets only", command);
        } catch (IOException e) {
            log.warn("Semgrep not found ('{}'); reviews will cover Java and secrets only. "
                + "Install it (pip install semgrep) or set CODELENS_SEMGREP_COMMAND.", command);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return false;
    }

    private static String tail(Path err) {
        try {
            String s = Files.readString(err, StandardCharsets.UTF_8).strip();
            return s.length() > 500 ? s.substring(s.length() - 500) : s;
        } catch (IOException e) {
            return "";
        }
    }

    private static void deleteQuietly(Path dir) {
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // temp folder; the OS cleans what is left
                }
            });
        } catch (IOException ignored) {
            // same
        }
    }
}
