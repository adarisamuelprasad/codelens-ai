package com.codelens.diff;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Which files of a PR CodeLens reads, and what language each one is.
 *
 * Every language gets the secret scan; the languages Semgrep parses also get
 * the CodeLens rule pack; Java additionally gets PMD and the JavaParser rules.
 * The language name doubles as the Markdown fence tag and as the hint the AI
 * service is given, so it uses the names those expect.
 */
public final class Languages {

    private Languages() {}

    private static final Map<String, String> BY_EXTENSION = Map.ofEntries(
        Map.entry("java", "java"),
        Map.entry("kt", "kotlin"), Map.entry("kts", "kotlin"),
        Map.entry("scala", "scala"), Map.entry("groovy", "groovy"),
        Map.entry("py", "python"), Map.entry("pyw", "python"),
        Map.entry("js", "javascript"), Map.entry("mjs", "javascript"), Map.entry("cjs", "javascript"),
        Map.entry("jsx", "javascript"),
        Map.entry("ts", "typescript"), Map.entry("mts", "typescript"), Map.entry("cts", "typescript"),
        Map.entry("tsx", "typescript"),
        Map.entry("go", "go"),
        Map.entry("cs", "csharp"),
        Map.entry("php", "php"),
        Map.entry("rb", "ruby"),
        Map.entry("rs", "rust"),
        Map.entry("c", "c"), Map.entry("h", "c"),
        Map.entry("cc", "cpp"), Map.entry("cpp", "cpp"), Map.entry("cxx", "cpp"), Map.entry("hpp", "cpp"),
        Map.entry("hh", "cpp"),
        Map.entry("swift", "swift"),
        Map.entry("dart", "dart"),
        Map.entry("lua", "lua"),
        Map.entry("r", "r"),
        Map.entry("pl", "perl"), Map.entry("pm", "perl"),
        Map.entry("ex", "elixir"), Map.entry("exs", "elixir"),
        Map.entry("sh", "bash"), Map.entry("bash", "bash"), Map.entry("zsh", "bash"),
        Map.entry("ps1", "powershell"),
        Map.entry("sql", "sql"),
        Map.entry("vue", "vue"), Map.entry("svelte", "svelte"),
        Map.entry("html", "html"), Map.entry("htm", "html"),
        Map.entry("tf", "hcl"), Map.entry("hcl", "hcl"),
        Map.entry("yml", "yaml"), Map.entry("yaml", "yaml"),
        Map.entry("json", "json"),
        Map.entry("xml", "xml"),
        Map.entry("properties", "properties"),
        Map.entry("toml", "toml"),
        Map.entry("ini", "ini"), Map.entry("cfg", "ini"), Map.entry("conf", "ini"),
        Map.entry("env", "dotenv"),
        Map.entry("gradle", "groovy")
    );

    /** Files with no extension that are still source or config. */
    private static final Map<String, String> BY_NAME = Map.of(
        "dockerfile", "dockerfile",
        "makefile", "makefile",
        "jenkinsfile", "groovy",
        "gemfile", "ruby",
        "rakefile", "ruby");

    /** Languages the Semgrep rule pack has rules for (Java has its own analyzers). */
    public static final Set<String> SEMGREP = Set.of(
        "python", "javascript", "typescript", "go", "csharp", "php", "ruby", "kotlin", "c", "cpp", "bash");

    /** Configuration, not code: only the secret scan applies. */
    public static final Set<String> CONFIG = Set.of(
        "yaml", "json", "xml", "properties", "toml", "ini", "dotenv", "hcl", "dockerfile", "makefile");

    // Generated, vendored or minified: nobody reviews these line by line.
    private static final List<String> SKIP_DIRS = List.of(
        "node_modules/", "vendor/", "dist/", "build/", "target/", "out/", ".next/", "__pycache__/",
        "venv/", ".venv/", "bower_components/", "Pods/", "third_party/", "generated/");
    private static final List<String> SKIP_SUFFIXES = List.of(
        ".min.js", ".min.css", ".bundle.js", ".map", ".lock", "-lock.json", ".lock.json",
        ".pb.go", "_pb2.py", ".g.dart", ".designer.cs", ".snap");
    private static final Set<String> SKIP_NAMES = Set.of(
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "cargo.lock", "go.sum",
        "composer.lock", "gemfile.lock", "pipfile.lock");

    /** The language of a path, or null when CodeLens does not read that kind of file. */
    public static String of(String path) {
        String name = fileName(path).toLowerCase(Locale.ROOT);
        if (name.equals(".env") || name.startsWith(".env.")) return "dotenv";
        String byName = BY_NAME.get(name);
        if (byName != null) return byName;
        int dot = name.lastIndexOf('.');
        if (dot < 0) return null;
        return BY_EXTENSION.get(name.substring(dot + 1));
    }

    /** True when a PR file should be fetched and analysed at all. */
    public static boolean reviewable(String path) {
        if (of(path) == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        String name = fileName(lower);
        if (SKIP_NAMES.contains(name)) return false;
        for (String s : SKIP_SUFFIXES) if (lower.endsWith(s.toLowerCase(Locale.ROOT))) return false;
        String dirs = "/" + lower;
        for (String d : SKIP_DIRS) if (dirs.contains("/" + d.toLowerCase(Locale.ROOT))) return false;
        return true;
    }

    public static boolean isConfig(String language) {
        return language != null && CONFIG.contains(language);
    }

    static String fileName(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }
}
