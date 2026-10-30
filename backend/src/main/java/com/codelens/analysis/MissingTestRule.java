package com.codelens.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.springframework.stereotype.Component;

import com.codelens.diff.ChangedFile;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;

/**
 * PR-level rule: production behaviour changed and no test changed with it.
 * "Behaviour" means a public method in a concrete class whose body has real
 * logic and whose lines this PR touched. Getters, setters, configuration and
 * the application's main class are left alone.
 */
@Component
public class MissingTestRule {

    private static final Set<String> CONFIG_ANNOTATIONS = Set.of(
        "Configuration", "SpringBootApplication", "ConfigurationProperties", "Entity", "Embeddable");

    public List<Finding> analyze(List<ChangedFile> files) {
        List<ChangedFile> tests = files.stream().filter(ChangedFile::isTest).toList();
        // Test names without their suffix: "PortUnificationServerTest" -> "portunificationserver".
        List<String> testBases = tests.stream()
            .map(f -> simpleName(f.path()).toLowerCase(Locale.ROOT).replaceAll("(tests?|it)$", "")).toList();
        // Modules (the path before src/test/java) where this PR touched any test,
        // fixtures included: real PRs often cover a change through shared test services.
        Set<String> testedModules = tests.stream().map(f -> module(f.path())).filter(m -> m != null)
            .collect(java.util.stream.Collectors.toSet());

        List<Finding> out = new ArrayList<>();
        for (ChangedFile f : files) {
            if (f.isTest() || !f.path().endsWith(".java")) continue;
            String module = module(f.path());
            if (module != null && testedModules.contains(module)) continue;
            // Nested classes are tested through their file's class (Outer.Builder -> OuterTest).
            String fileClass = simpleName(f.path()).toLowerCase(Locale.ROOT);
            if (testBases.stream().anyMatch(t -> !t.isEmpty() && (fileClass.contains(t) || t.contains(fileClass)))) continue;
            JavaRules.parse(f).ifPresent(cu -> {
                for (ClassOrInterfaceDeclaration type : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                    if (type.isInterface() || type.isAbstract() || isConfiguration(type)) continue;
                    String cls = type.getNameAsString();
                    MethodDeclaration changed = firstChangedLogicMethod(type, f);
                    if (changed != null) {
                        RuleCatalog.Rule rule = RuleCatalog.CODELENS.get("MISSING_TEST");
                        int line = changed.getBegin().map(p -> p.line).orElse(1);
                        out.add(new Finding("MISSING_TEST", "codelens", rule.category(), rule.severity(), f.path(), line,
                            cls + "." + changed.getNameAsString() + "() changed, but no test for " + cls
                                + " was added or updated in this PR."));
                    }
                }
            });
        }
        return out;
    }

    private static MethodDeclaration firstChangedLogicMethod(ClassOrInterfaceDeclaration type, ChangedFile f) {
        for (MethodDeclaration m : type.getMethods()) {
            if (!m.isPublic() || m.getBody().isEmpty() || isAccessor(m)) continue;
            if (m.getNameAsString().equals("main")) continue;
            int from = m.getBegin().map(p -> p.line).orElse(0);
            int to = m.getEnd().map(p -> p.line).orElse(0);
            for (int line = from; line <= to; line++) {
                if (f.addedLines().contains(line)) return m;
            }
        }
        return null;
    }

    private static boolean isAccessor(MethodDeclaration m) {
        String n = m.getNameAsString();
        var body = m.getBody().map(b -> b.getStatements()).orElse(null);
        int statements = body == null ? 0 : body.size();
        boolean named = n.startsWith("get") || n.startsWith("set") || n.startsWith("is") || n.startsWith("with")
            || n.equals("toString") || n.equals("equals") || n.equals("hashCode");
        // Fluent builder setter: this.x = x; return this;
        boolean fluent = statements == 2 && body.get(1).toString().replace(" ", "").equals("returnthis;");
        return named && (statements <= 1 || fluent);
    }

    /** "dubbo-rpc/dubbo-rpc-triple/" for ".../src/main/java/..." or ".../src/test/java/...", else null. */
    static String module(String path) {
        for (String marker : List.of("src/main/java/", "src/test/java/")) {
            int i = path.indexOf(marker);
            if (i >= 0) return path.substring(0, i);
        }
        return null;
    }

    private static boolean isConfiguration(ClassOrInterfaceDeclaration type) {
        return type.getAnnotations().stream().anyMatch(a -> CONFIG_ANNOTATIONS.contains(a.getNameAsString()))
            || type.getNameAsString().endsWith("Dto") || type.getNameAsString().endsWith("Request")
            || type.getNameAsString().endsWith("Response");
    }

    private static String simpleName(String path) {
        String file = path.substring(path.lastIndexOf('/') + 1);
        return file.endsWith(".java") ? file.substring(0, file.length() - 5) : file;
    }
}
