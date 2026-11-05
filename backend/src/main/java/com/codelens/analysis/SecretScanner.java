package com.codelens.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

import com.codelens.diff.ChangedFile;
import com.codelens.diff.Languages;

/**
 * HARDCODED_SECRET for every file that is not Java (JavaRules covers Java
 * through its AST): Python, Go, JavaScript, a .env file, application.yml,
 * a Terraform variable, anything with text in it.
 *
 * Without a parser per language it works line by line, which is enough for
 * the two shapes that matter: a known token format anywhere on a line, and a
 * secret-named key assigned a literal value. Names, value tests and
 * placeholders are JavaRules' own, so the verdict on a value does not depend
 * on which language it was written in.
 */
@Component
public class SecretScanner {

    // name = "value", name: 'value', name := "value", "name": "value", name => 'value'
    private static final Pattern QUOTED_ASSIGNMENT = Pattern.compile(
        "[\"']?(?<name>[A-Za-z_][A-Za-z0-9_.\\-]*)[\"']?\\s*(?::=|=>|=|:)\\s*(?<q>[\"'`])(?<value>[^\"'`]*)\\k<q>");
    // Config files also write values bare: DB_PASSWORD=s3cr3t, password: s3cr3t
    private static final Pattern BARE_ASSIGNMENT = Pattern.compile(
        "^\\s*(?:export\\s+)?(?<name>[A-Za-z_][A-Za-z0-9_.\\-]*)\\s*[:=]\\s*(?<value>[^\\s#'\"`]+)\\s*(?:#.*)?$");
    // Example env files exist to show the shape of a secret, not to hold one.
    private static final Pattern EXAMPLE_FILE = Pattern.compile(
        "(?i).*(\\.example|\\.sample|\\.template|\\.dist|\\.tmpl)$|.*example.*");

    public List<Finding> analyze(List<ChangedFile> files) {
        List<Finding> out = new ArrayList<>();
        for (ChangedFile f : files) {
            if (f.isJava()) continue;
            String language = f.language();
            boolean config = Languages.isConfig(language);
            boolean namedSecretsApply = !f.isTest() && !EXAMPLE_FILE.matcher(f.path()).matches();
            String[] lines = f.content().split("\n", -1);
            for (int i = 0; i < lines.length; i++) {
                int lineNo = i + 1;
                if (!f.addedLines().contains(lineNo)) continue;
                String line = lines[i];
                if (JavaRules.KNOWN_TOKEN.matcher(line).find()) {
                    out.add(finding(f, lineNo, "This line contains a string in the format of a real access token "
                        + "or private key. Remove it, rotate it now, and load it from a secret store."));
                    continue;
                }
                if (!namedSecretsApply) continue;
                String name = namedSecret(line, config);
                if (name != null) {
                    out.add(finding(f, lineNo, "'" + name + "' is a credential written into the "
                        + (config ? "configuration" : "source")
                        + ". Read it from the environment or a secret manager, and rotate the current value."));
                }
            }
        }
        return out;
    }

    /** The secret-named key assigned a literal on this line, or null. */
    static String namedSecret(String line, boolean config) {
        Matcher q = QUOTED_ASSIGNMENT.matcher(line);
        while (q.find()) {
            if (isSecret(q.group("name"), q.group("value"))) return q.group("name");
        }
        if (config) {
            Matcher b = BARE_ASSIGNMENT.matcher(line);
            if (b.matches() && isSecret(b.group("name"), b.group("value"))) return b.group("name");
        }
        return null;
    }

    private static boolean isSecret(String name, String value) {
        // The last segment names the value: spring.datasource.password -> password.
        String key = name.substring(name.lastIndexOf('.') + 1).replace('-', '_');
        if (!JavaRules.SECRET_NAME.matcher(key).matches() || JavaRules.NOT_A_SECRET_NAME.matcher(key).matches()) {
            return false;
        }
        String v = value.trim();
        // References to the real value, not the value: $DB_PASS, %(pw)s, env("X"), ENV['X'], {{ secret }}
        if (v.startsWith("$") || v.startsWith("%") || v.startsWith("{") || v.startsWith("<")) return false;
        String lower = v.toLowerCase(Locale.ROOT);
        if (lower.startsWith("env") || lower.contains("environ") || lower.startsWith("process.")
            || lower.startsWith("secrets.") || lower.startsWith("vault:")) {
            return false;
        }
        return JavaRules.looksLikeSecretValue(v);
    }

    private static Finding finding(ChangedFile f, int line, String message) {
        RuleCatalog.Rule rule = RuleCatalog.CODELENS.get("HARDCODED_SECRET");
        return new Finding("HARDCODED_SECRET", "codelens", rule.category(), rule.severity(), f.path(), line, message);
    }
}
