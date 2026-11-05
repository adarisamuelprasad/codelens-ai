package com.codelens.analysis;

import static com.codelens.analysis.Finding.Category.BUG;
import static com.codelens.analysis.Finding.Category.MAINTAINABILITY;
import static com.codelens.analysis.Finding.Category.RELIABILITY;
import static com.codelens.analysis.Finding.Category.SECURITY;
import static com.codelens.analysis.Finding.Category.TESTING;
import static com.codelens.analysis.Finding.Severity.HIGH;
import static com.codelens.analysis.Finding.Severity.LOW;
import static com.codelens.analysis.Finding.Severity.MEDIUM;

import java.util.Map;

import com.codelens.analysis.Finding.Category;
import com.codelens.analysis.Finding.Severity;

/**
 * Every rule CodeLens can report, with its category, severity and a one-line
 * description. The single source of truth: PMD rules not listed here are not
 * in rulesets/codelens.xml either (RuleCatalogTest checks both directions).
 *
 * PMD ships hundreds of rules; most are style. These are the ones that point
 * at bugs, leaks, security holes or code that misleads its reader, which is
 * what a reviewer wants flagged on a PR.
 */
public final class RuleCatalog {

    public record Rule(Category category, Severity severity, String description) {}

    private RuleCatalog() {}

    /**
     * CodeLens's own rules. The first group runs on every language (Java via
     * JavaRules, the rest via the Semgrep pack in semgrep/codelens-rules.yml,
     * secrets via SecretScanner); the second is language-specific.
     */
    public static final Map<String, Rule> CODELENS = Map.ofEntries(
        Map.entry("SQL_INJECTION", new Rule(SECURITY, HIGH,
            "SQL built by concatenating, formatting or interpolating values into the query text instead of binding parameters.")),
        Map.entry("COMMAND_INJECTION", new Rule(SECURITY, HIGH,
            "An OS command built from non-constant values and handed to a shell (Runtime.exec, os.system, child_process.exec, sh -c, system()).")),
        Map.entry("CODE_INJECTION", new Rule(SECURITY, HIGH,
            "A string that is not a constant is executed as code (eval, exec, new Function, a string passed to setTimeout).")),
        Map.entry("INSECURE_DESERIALIZATION", new Rule(SECURITY, HIGH,
            "A deserialiser that can construct arbitrary objects or run code while loading (pickle, yaml.load, unserialize, Marshal.load, BinaryFormatter).")),
        Map.entry("HARDCODED_SECRET", new Rule(SECURITY, HIGH,
            "A credential, key or token written into the source or a config file as a literal.")),
        Map.entry("UNSAFE_BUFFER_FUNCTION", new Rule(SECURITY, HIGH,
            "A C string function that writes into a buffer without a size limit (gets, strcpy, strcat, sprintf/scanf with %s).")),
        Map.entry("TLS_VERIFY_DISABLED", new Rule(SECURITY, MEDIUM,
            "TLS certificate or hostname verification switched off, so the connection can be intercepted.")),
        Map.entry("UNSAFE_HTML", new Rule(SECURITY, MEDIUM,
            "A value that is not a constant is written into a page as raw HTML or marked safe, so markup in it runs (cross-site scripting).")),
        Map.entry("PERMISSIVE_CORS", new Rule(SECURITY, MEDIUM,
            "CORS configured to allow every origin, so any website can call this endpoint from a visitor's browser.")),
        Map.entry("DEBUG_MODE", new Rule(SECURITY, MEDIUM,
            "A framework's debug mode switched on in code, which exposes stack traces, settings or an interactive debugger.")),
        Map.entry("CSRF_DISABLED", new Rule(SECURITY, LOW,
            "CSRF protection switched off. Fine for a stateless token API, a hole for cookie sessions.")),
        Map.entry("SWALLOWED_EXCEPTION", new Rule(RELIABILITY, MEDIUM,
            "A catch/except block that ignores the error or only prints it, then carries on as if nothing failed.")),
        Map.entry("PROXY_ANNOTATION_ON_PRIVATE", new Rule(BUG, MEDIUM,
            "@Transactional, @Async or @Cacheable on a private or final method, which Spring proxies silently ignore.")),
        Map.entry("MISSING_TEST", new Rule(TESTING, MEDIUM,
            "New or changed public behaviour in production code with no test file touched in this PR.")),
        Map.entry("MUTABLE_DEFAULT_ARGUMENT", new Rule(BUG, MEDIUM,
            "Python: a list, dict or set as a default argument is shared by every call that omits it.")),
        Map.entry("LITERAL_IDENTITY_COMPARISON", new Rule(BUG, HIGH,
            "Python: 'is' used to compare with a string or number literal; it tests identity, not equality.")),
        Map.entry("NAN_COMPARISON", new Rule(BUG, HIGH,
            "JavaScript: comparing with NaN using == or ===, which is always false.")),
        Map.entry("DEFER_IN_LOOP", new Rule(RELIABILITY, MEDIUM,
            "Go: defer inside a loop, so every resource opened in the loop stays open until the function returns."))
    );

    public static final Map<String, Rule> PMD = Map.ofEntries(
        Map.entry("EmptyCatchBlock", new Rule(RELIABILITY, MEDIUM, "An exception is caught and silently ignored.")),
        Map.entry("CloseResource", new Rule(RELIABILITY, MEDIUM, "A stream, connection or statement may not be closed on every path.")),
        Map.entry("CompareObjectsWithEquals", new Rule(BUG, MEDIUM, "Objects compared with == instead of equals().")),
        Map.entry("UseEqualsToCompareStrings", new Rule(BUG, HIGH, "Strings compared with == or != instead of equals().")),
        Map.entry("EqualsNull", new Rule(BUG, MEDIUM, "equals(null) is always false; compare with == null.")),
        Map.entry("ReturnFromFinallyBlock", new Rule(BUG, HIGH, "A return in finally discards any exception thrown in try.")),
        Map.entry("MisplacedNullCheck", new Rule(BUG, HIGH, "The null check comes after the value was already dereferenced.")),
        Map.entry("BrokenNullCheck", new Rule(BUG, HIGH, "This null check throws NullPointerException itself.")),
        Map.entry("OverrideBothEqualsAndHashcode", new Rule(BUG, HIGH, "equals() and hashCode() must be overridden together.")),
        Map.entry("ConstructorCallsOverridableMethod", new Rule(BUG, MEDIUM, "A constructor calls a method a subclass can override, before the subclass is initialised.")),
        Map.entry("ImplicitSwitchFallThrough", new Rule(BUG, MEDIUM, "A switch case falls through to the next without a break.")),
        Map.entry("AvoidDecimalLiteralsInBigDecimalConstructor", new Rule(BUG, MEDIUM, "new BigDecimal(0.1) captures the binary rounding error; use a String or valueOf.")),
        Map.entry("ClassCastExceptionWithToArray", new Rule(BUG, HIGH, "Casting the result of toArray() throws ClassCastException.")),
        Map.entry("AvoidCatchingNPE", new Rule(RELIABILITY, MEDIUM, "Catching NullPointerException hides the bug that caused it.")),
        Map.entry("AvoidCatchingThrowable", new Rule(RELIABILITY, MEDIUM, "Catching Throwable also swallows Errors like OutOfMemoryError.")),
        Map.entry("PreserveStackTrace", new Rule(RELIABILITY, MEDIUM, "A new exception is thrown from a catch without the original cause.")),
        Map.entry("DoubleCheckedLocking", new Rule(BUG, HIGH, "Double-checked locking without volatile is broken under the Java memory model.")),
        Map.entry("NonThreadSafeSingleton", new Rule(BUG, MEDIUM, "Lazy singleton creation that is not thread-safe.")),
        Map.entry("UnsynchronizedStaticFormatter", new Rule(BUG, MEDIUM, "A static DateFormat/NumberFormat shared across threads; they are not thread-safe.")),
        Map.entry("HardCodedCryptoKey", new Rule(SECURITY, HIGH, "A cryptographic key written into the source.")),
        Map.entry("InsecureCryptoIv", new Rule(SECURITY, HIGH, "A hard-coded initialisation vector makes encryption predictable.")),
        Map.entry("UnusedPrivateMethod", new Rule(MAINTAINABILITY, LOW, "A private method nothing calls.")),
        Map.entry("UnusedLocalVariable", new Rule(MAINTAINABILITY, LOW, "A local variable that is never read.")),
        Map.entry("UnusedPrivateField", new Rule(MAINTAINABILITY, LOW, "A private field that is never read.")),
        Map.entry("AvoidPrintStackTrace", new Rule(MAINTAINABILITY, LOW, "printStackTrace() writes to stderr instead of the application log.")),
        Map.entry("SystemPrintln", new Rule(MAINTAINABILITY, LOW, "System.out/err in application code instead of a logger."))
    );

    /** The rule for an id from either source, or null. */
    public static Rule get(String ruleId) {
        Rule r = CODELENS.get(ruleId);
        return r != null ? r : PMD.get(ruleId);
    }
}
