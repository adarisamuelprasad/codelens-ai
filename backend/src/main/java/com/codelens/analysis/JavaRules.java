package com.codelens.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.codelens.diff.ChangedFile;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ParserConfiguration.LanguageLevel;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.MethodReferenceExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.TextBlockLiteralExpr;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.Statement;

/**
 * CodeLens's own rules, for problems PMD does not catch well on source alone:
 * injection, secrets, permissive web security, Spring proxy pitfalls and
 * swallowed exceptions. Each rule is a heuristic over the syntax tree, tuned
 * to stay quiet on the common safe forms (bound parameters, constants,
 * placeholders) because a noisy reviewer gets ignored.
 */
@Component
public class JavaRules {

    private static final Logger log = LoggerFactory.getLogger(JavaRules.class);

    static final Set<String> SQL_SINKS = Set.of(
        "executeQuery", "executeUpdate", "executeLargeUpdate", "execute", "addBatch",
        "prepareStatement", "prepareCall", "createQuery", "createNativeQuery", "createSQLQuery",
        "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "update", "batchUpdate");

    private static final Pattern SQL_TEXT = Pattern.compile(
        "(?i)\\b(select|insert\\s+into|update|delete\\s+from|merge\\s+into|where|from|values|order\\s+by|group\\s+by)\\b");

    private static final Pattern SECRET_NAME = Pattern.compile(
        "(?i).*(password|passwd|pwd|secret|api_?key|access_?key|private_?key|token|credential).*");
    // Names that mention a secret without holding one: TOKEN_HEADER, PASSWORD_PARAM, SECRET_PROPERTY...
    private static final Pattern NOT_A_SECRET_NAME = Pattern.compile(
        "(?i).*(header|param|field|name|label|url|uri|endpoint|path|prefix|property|prop|attr|message|msg|"
        + "pattern|regex|format|type|key_name|column|claim|cookie|query|policy|length|expir|ttl|validity).*");
    private static final Pattern PLACEHOLDER = Pattern.compile(
        "(?i).*(\\$\\{|\\{\\{|changeme|change_me|example|dummy|placeholder|your[_-]|<[^>]+>|xxx|\\*\\*\\*).*");
    // Formats that are a secret whatever the variable is called.
    private static final Pattern KNOWN_TOKEN = Pattern.compile(
        "(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\\-]{35}"
        + "|sk-[A-Za-z0-9_\\-]{20,}|xox[baprs]-[A-Za-z0-9\\-]{10,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)");

    private static final Set<String> PROXY_ANNOTATIONS = Set.of(
        "Transactional", "Async", "Cacheable", "CachePut", "CacheEvict", "Retryable");
    private static final Set<String> CORS_ORIGIN_CALLS = Set.of(
        "allowedOrigins", "allowedOriginPatterns", "addAllowedOrigin", "addAllowedOriginPattern",
        "setAllowedOrigins", "setAllowedOriginPatterns");

    public List<Finding> analyze(List<ChangedFile> files) {
        List<Finding> out = new ArrayList<>();
        for (ChangedFile f : files) {
            parse(f).ifPresent(cu -> analyzeUnit(f, cu, out));
        }
        return out;
    }

    static Optional<CompilationUnit> parse(ChangedFile f) {
        JavaParser parser = new JavaParser(new ParserConfiguration().setLanguageLevel(LanguageLevel.JAVA_21));
        ParseResult<CompilationUnit> r = parser.parse(f.content());
        if (r.getResult().isEmpty() || !r.isSuccessful()) {
            log.info("JavaParser could not parse {}; CodeLens rules skipped for it", f.path());
            return Optional.empty();
        }
        return r.getResult();
    }

    private void analyzeUnit(ChangedFile f, CompilationUnit cu, List<Finding> out) {
        cu.findAll(MethodCallExpr.class).forEach(call -> {
            sqlInjection(f, call, out);
            commandInjection(f, call, out);
            corsCall(f, call, out);
            csrfDisabled(f, call, out);
        });
        cu.findAll(ObjectCreationExpr.class).forEach(n -> processBuilder(f, n, out));
        cu.findAll(VariableDeclarator.class).forEach(v -> secretVariable(f, v, out));
        cu.findAll(StringLiteralExpr.class).forEach(s -> knownToken(f, s, s.getValue(), out));
        cu.findAll(TextBlockLiteralExpr.class).forEach(s -> knownToken(f, s, s.getValue(), out));
        cu.findAll(AnnotationExpr.class).forEach(a -> corsAnnotation(f, a, out));
        cu.findAll(MethodDeclaration.class).forEach(m -> proxyOnPrivate(f, m, out));
        cu.findAll(CatchClause.class).forEach(c -> swallowed(f, c, out));
    }

    // ---- SQL injection -------------------------------------------------------

    private void sqlInjection(ChangedFile f, MethodCallExpr call, List<Finding> out) {
        if (!SQL_SINKS.contains(call.getNameAsString()) || call.getArguments().isEmpty()) return;
        if (taintedSql(call.getArgument(0), enclosingCallable(call), 0)) {
            add(out, "SQL_INJECTION", f, call, "The query passed to " + call.getNameAsString()
                + "() is built from runtime values. Use a ? or :named parameter and bind the value.");
        }
    }

    /** True when the expression is SQL text with a non-constant value spliced in. */
    static boolean taintedSql(Expression e, Node scope, int depth) {
        if (depth > 3) return false;
        if (e.isEnclosedExpr()) return taintedSql(e.asEnclosedExpr().getInner(), scope, depth);
        if (e.isBinaryExpr() && e.asBinaryExpr().getOperator() == BinaryExpr.Operator.PLUS) {
            List<Expression> parts = new ArrayList<>();
            flattenPlus(e, parts);
            boolean sql = parts.stream().anyMatch(JavaRules::isSqlLiteral);
            boolean dynamic = parts.stream().anyMatch(p -> !isConstant(p));
            return sql && dynamic;
        }
        if (e.isMethodCallExpr()) {
            MethodCallExpr m = e.asMethodCallExpr();
            String name = m.getNameAsString();
            if (name.equals("format") && m.getArguments().size() >= 2 && isSqlLiteral(m.getArgument(0))) return true;
            if (name.equals("formatted") && m.getScope().filter(JavaRules::isSqlLiteral).isPresent()
                && !m.getArguments().isEmpty()) return true;
            if (name.equals("toString") && m.getScope().filter(Expression::isNameExpr).isPresent()) {
                return taintedBuilder(m.getScope().get().asNameExpr().getNameAsString(), scope);
            }
            return false;
        }
        if (e.isNameExpr() && scope != null) {
            String var = e.asNameExpr().getNameAsString();
            for (VariableDeclarator v : scope.findAll(VariableDeclarator.class)) {
                if (v.getNameAsString().equals(var) && v.getInitializer().isPresent()
                    && taintedSql(v.getInitializer().get(), scope, depth + 1)) return true;
            }
            for (AssignExpr a : scope.findAll(AssignExpr.class)) {
                if (!a.getTarget().isNameExpr() || !a.getTarget().asNameExpr().getNameAsString().equals(var)) continue;
                if (taintedSql(a.getValue(), scope, depth + 1)) return true;
                // query += someValue, after query started as SQL text
                if (a.getOperator() == AssignExpr.Operator.PLUS && !isConstant(a.getValue())
                    && startsAsSql(var, scope)) return true;
            }
        }
        return false;
    }

    private static boolean taintedBuilder(String builder, Node scope) {
        if (scope == null) return false;
        boolean sql = false, dynamic = false;
        for (MethodCallExpr m : scope.findAll(MethodCallExpr.class)) {
            if (!m.getNameAsString().equals("append") || m.getArguments().size() != 1) continue;
            if (!rootName(m).equals(builder)) continue;
            Expression arg = m.getArgument(0);
            if (isSqlLiteral(arg)) sql = true;
            else if (!isConstant(arg)) dynamic = true;
        }
        for (ObjectCreationExpr n : scope.findAll(ObjectCreationExpr.class)) {
            if (n.getArguments().size() == 1 && isSqlLiteral(n.getArgument(0))) sql = true;
        }
        return sql && dynamic;
    }

    /** The variable a chained call starts from: sb.append(a).append(b) -> "sb". */
    private static String rootName(MethodCallExpr m) {
        Expression e = m;
        while (e.isMethodCallExpr() && e.asMethodCallExpr().getScope().isPresent()) {
            e = e.asMethodCallExpr().getScope().get();
        }
        return e.isNameExpr() ? e.asNameExpr().getNameAsString() : "";
    }

    private static boolean startsAsSql(String var, Node scope) {
        return scope.findAll(VariableDeclarator.class).stream().anyMatch(v ->
            v.getNameAsString().equals(var) && v.getInitializer().map(JavaRules::containsSqlLiteral).orElse(false));
    }

    private static boolean containsSqlLiteral(Expression e) {
        return isSqlLiteral(e) || e.findAll(StringLiteralExpr.class).stream().anyMatch(JavaRules::isSqlLiteral);
    }

    private static void flattenPlus(Expression e, List<Expression> parts) {
        if (e.isBinaryExpr() && e.asBinaryExpr().getOperator() == BinaryExpr.Operator.PLUS) {
            flattenPlus(e.asBinaryExpr().getLeft(), parts);
            flattenPlus(e.asBinaryExpr().getRight(), parts);
        } else if (e.isEnclosedExpr()) {
            flattenPlus(e.asEnclosedExpr().getInner(), parts);
        } else {
            parts.add(e);
        }
    }

    private static boolean isSqlLiteral(Expression e) {
        String text = e.isStringLiteralExpr() ? e.asStringLiteralExpr().getValue()
            : e.isTextBlockLiteralExpr() ? e.asTextBlockLiteralExpr().getValue() : null;
        return text != null && SQL_TEXT.matcher(text).find();
    }

    /** Literals and UPPER_CASE constants are not attacker-controlled. */
    private static boolean isConstant(Expression e) {
        if (e.isLiteralExpr()) return true;
        if (e.isNameExpr()) return e.asNameExpr().getNameAsString().matches("[A-Z][A-Z0-9_]*");
        if (e.isFieldAccessExpr()) return e.asFieldAccessExpr().getNameAsString().matches("[A-Z][A-Z0-9_]*");
        return false;
    }

    private static Node enclosingCallable(Node n) {
        return n.findAncestor(CallableDeclaration.class).map(c -> (Node) c)
            .orElseGet(() -> n.findAncestor(LambdaExpr.class).map(l -> (Node) l).orElse(null));
    }

    // ---- Command injection ---------------------------------------------------

    // Programs that interpret their argument as a command line.
    private static final Set<String> SHELLS = Set.of(
        "sh", "bash", "zsh", "/bin/sh", "/bin/bash", "cmd", "cmd.exe", "powershell", "powershell.exe", "-c", "/c");

    private void commandInjection(ChangedFile f, MethodCallExpr call, List<Finding> out) {
        if (call.getArguments().isEmpty()) return;
        String name = call.getNameAsString();
        Node scope = enclosingCallable(call);
        if (name.equals("exec") && call.getScope().filter(s -> isRuntime(s, scope)).isPresent()) {
            Expression cmd = call.getArgument(0);
            // exec(String) splits the string itself, so any runtime value in it can add
            // arguments or chain commands; exec(String[]) only matters through a shell.
            boolean dynamicString = !cmd.isArrayCreationExpr() && !isConstantArray(cmd, scope) && !isConstant(cmd);
            if (dynamicString || shellWithDynamic(argumentsOf(cmd, scope), scope)) {
                add(out, "COMMAND_INJECTION", f, call, "Runtime.exec() runs a command built at runtime. "
                    + "Pass a fixed program and separate arguments, and validate any user input.");
            }
        }
        // pb.command(list) / pb.command("sh", "-c", x)
        if (name.equals("command") && shellWithDynamic(argumentsOfAll(call.getArguments(), scope), scope)) {
            add(out, "COMMAND_INJECTION", f, call, "A shell command is assembled from runtime values. "
                + "Run the program directly with fixed arguments instead of through a shell.");
        }
    }

    private void processBuilder(ChangedFile f, ObjectCreationExpr n, List<Finding> out) {
        if (!n.getType().getNameAsString().equals("ProcessBuilder")) return;
        List<Expression> args = argumentsOfAll(n.getArguments(), enclosingCallable(n));
        boolean concatenated = args.stream().anyMatch(a -> a.isBinaryExpr() && !isConstant(a));
        if (concatenated || shellWithDynamic(args, enclosingCallable(n))) {
            add(out, "COMMAND_INJECTION", f, n, "A shell command is assembled from runtime values. "
                + "Run the program directly with fixed arguments instead of through a shell.");
        }
    }

    /** Runtime.getRuntime() itself, or a variable holding it. */
    private static boolean isRuntime(Expression e, Node scope) {
        if (e.toString().contains("getRuntime()")) return true;
        if (!e.isNameExpr() || scope == null) return false;
        String var = e.asNameExpr().getNameAsString();
        return scope.findAll(VariableDeclarator.class).stream().anyMatch(v -> v.getNameAsString().equals(var)
            && (v.getTypeAsString().equals("Runtime") || v.getTypeAsString().equals("java.lang.Runtime")
                || v.getInitializer().map(i -> i.toString().contains("getRuntime()")).orElse(false)));
    }

    /**
     * The command-line pieces an argument stands for: the elements of an array
     * literal or of a local array/list (initialiser and add() calls), else itself.
     */
    private static List<Expression> argumentsOf(Expression e, Node scope) {
        List<Expression> out = new ArrayList<>();
        if (e.isArrayCreationExpr() && e.asArrayCreationExpr().getInitializer().isPresent()) {
            out.addAll(e.asArrayCreationExpr().getInitializer().get().getValues());
        } else if (e.isArrayInitializerExpr()) {
            out.addAll(e.asArrayInitializerExpr().getValues());
        } else if (e.isNameExpr() && scope != null) {
            String var = e.asNameExpr().getNameAsString();
            boolean collection = false;
            for (VariableDeclarator v : scope.findAll(VariableDeclarator.class)) {
                if (!v.getNameAsString().equals(var) || v.getInitializer().isEmpty()) continue;
                Expression init = v.getInitializer().get();
                if (init.isArrayInitializerExpr() || init.isArrayCreationExpr()) {
                    out.addAll(argumentsOf(init, null));
                    collection = true;
                } else if (init.isMethodCallExpr() && Set.of("asList", "of").contains(init.asMethodCallExpr().getNameAsString())) {
                    out.addAll(init.asMethodCallExpr().getArguments());
                    collection = true;
                } else if (init.isObjectCreationExpr()) {
                    collection = true; // new ArrayList<>(), filled by add() below
                }
            }
            for (MethodCallExpr m : scope.findAll(MethodCallExpr.class)) {
                if (m.getNameAsString().equals("add") && m.getArguments().size() == 1 && rootName(m).equals(var)) {
                    out.add(m.getArgument(0));
                    collection = true;
                }
            }
            if (!collection) out.add(e);
        } else {
            out.add(e);
        }
        return out;
    }

    private static List<Expression> argumentsOfAll(List<Expression> args, Node scope) {
        List<Expression> out = new ArrayList<>();
        for (Expression a : args) out.addAll(argumentsOf(a, scope));
        return out;
    }

    private static boolean shellWithDynamic(List<Expression> pieces, Node scope) {
        boolean shell = pieces.stream().anyMatch(p -> p.isStringLiteralExpr()
            && SHELLS.contains(p.asStringLiteralExpr().getValue().trim()));
        return shell && pieces.stream().anyMatch(p -> !isConstant(p));
    }

    private static boolean isConstantArray(Expression e, Node scope) {
        if (!e.isNameExpr() || scope == null) return false;
        List<Expression> pieces = argumentsOf(e, scope);
        return !(pieces.size() == 1 && pieces.get(0) == e) && pieces.stream().allMatch(JavaRules::isConstant);
    }

    // ---- Secrets -------------------------------------------------------------

    private void secretVariable(ChangedFile f, VariableDeclarator v, List<Finding> out) {
        if (f.isTest()) return; // test fixtures are full of fake passwords; KNOWN_TOKEN still covers real ones
        String name = v.getNameAsString();
        if (!SECRET_NAME.matcher(name).matches() || NOT_A_SECRET_NAME.matcher(name).matches()) return;
        Optional<Expression> init = v.getInitializer();
        if (init.isEmpty() || !init.get().isStringLiteralExpr()) return;
        String value = init.get().asStringLiteralExpr().getValue();
        if (looksLikeSecretValue(value) && !KNOWN_TOKEN.matcher(value).find()) {
            add(out, "HARDCODED_SECRET", f, v, "'" + name + "' is a credential written into the source. "
                + "Read it from configuration or a secret manager, and rotate the current value.");
        }
    }

    static boolean looksLikeSecretValue(String value) {
        if (value.length() < 8 || value.contains(" ") || PLACEHOLDER.matcher(value).matches()) return false;
        boolean letter = value.chars().anyMatch(Character::isLetter);
        boolean other = value.chars().anyMatch(c -> !Character.isLetter(c));
        return (letter && other) || value.length() >= 20;
    }

    private void knownToken(ChangedFile f, Node literal, String value, List<Finding> out) {
        if (KNOWN_TOKEN.matcher(value).find()) {
            add(out, "HARDCODED_SECRET", f, literal, "This string matches the format of a real access token "
                + "or private key. Remove it, rotate it now, and load it from a secret store.");
        }
    }

    // ---- Web security --------------------------------------------------------

    private void corsAnnotation(ChangedFile f, AnnotationExpr a, List<Finding> out) {
        if (!a.getNameAsString().equals("CrossOrigin")) return;
        boolean open = a.isMarkerAnnotationExpr();
        if (a instanceof SingleMemberAnnotationExpr s) open = containsStar(s.getMemberValue());
        if (a instanceof NormalAnnotationExpr n) {
            boolean anyOrigin = false;
            for (MemberValuePair p : n.getPairs()) {
                String key = p.getNameAsString();
                if (key.equals("origins") || key.equals("value") || key.equals("originPatterns")) {
                    anyOrigin = true;
                    if (containsStar(p.getValue())) open = true;
                }
            }
            if (!anyOrigin) open = true; // @CrossOrigin(maxAge = 3600) still allows every origin
        }
        if (open) {
            add(out, "PERMISSIVE_CORS", f, a, "@CrossOrigin here allows every origin. List the front-end "
                + "origins that should call this endpoint.");
        }
    }

    private void corsCall(ChangedFile f, MethodCallExpr call, List<Finding> out) {
        if (CORS_ORIGIN_CALLS.contains(call.getNameAsString()) && call.getArguments().stream().anyMatch(JavaRules::containsStar)) {
            add(out, "PERMISSIVE_CORS", f, call, "CORS is configured to accept every origin. "
                + "List the allowed front-end origins explicitly.");
        }
    }

    private static boolean containsStar(Expression e) {
        return e.findAll(StringLiteralExpr.class).stream().anyMatch(s -> s.getValue().equals("*"))
            || (e.isStringLiteralExpr() && e.asStringLiteralExpr().getValue().equals("*"));
    }

    private void csrfDisabled(ChangedFile f, MethodCallExpr call, List<Finding> out) {
        boolean chained = call.getNameAsString().equals("disable")
            && call.getScope().filter(s -> s.isMethodCallExpr() && s.asMethodCallExpr().getNameAsString().equals("csrf")).isPresent();
        boolean lambda = call.getNameAsString().equals("csrf") && call.getArguments().size() == 1
            && (isDisableLambda(call.getArgument(0)) || isDisableReference(call.getArgument(0)));
        if (chained || lambda) {
            add(out, "CSRF_DISABLED", f, call, "CSRF protection is turned off. That is only safe when no "
                + "endpoint authenticates with cookies; confirm this API is token-only.");
        }
    }

    private static boolean isDisableLambda(Expression e) {
        return e.isLambdaExpr() && e.findAll(MethodCallExpr.class).stream().anyMatch(m -> m.getNameAsString().equals("disable"));
    }

    private static boolean isDisableReference(Expression e) {
        return e instanceof MethodReferenceExpr r && r.getIdentifier().equals("disable");
    }

    // ---- Spring and exceptions -----------------------------------------------

    private void proxyOnPrivate(ChangedFile f, MethodDeclaration m, List<Finding> out) {
        if (!(m.isPrivate() || m.isFinal() || m.isStatic())) return;
        for (AnnotationExpr a : m.getAnnotations()) {
            if (PROXY_ANNOTATIONS.contains(a.getNameAsString())) {
                String kind = m.isPrivate() ? "private" : m.isFinal() ? "final" : "static";
                add(out, "PROXY_ANNOTATION_ON_PRIVATE", f, a, "@" + a.getNameAsString() + " on a " + kind
                    + " method has no effect: Spring's proxy cannot intercept it. Make it public and call it "
                    + "through the bean, not from inside the same class.");
                return;
            }
        }
    }

    private void swallowed(ChangedFile f, CatchClause c, List<Finding> out) {
        List<Statement> body = c.getBody().getStatements();
        if (body.isEmpty() || body.size() > 2) return; // empty catch is PMD's EmptyCatchBlock
        boolean onlyPrints = body.stream().allMatch(s -> s instanceof ExpressionStmt es
            && es.getExpression().isMethodCallExpr() && isPrintOnly(es.getExpression().asMethodCallExpr()));
        if (onlyPrints) {
            add(out, "SWALLOWED_EXCEPTION", f, c, "This catch only prints the error and continues, so callers "
                + "see success. Log it with context and rethrow, or handle it.");
        }
    }

    private static boolean isPrintOnly(MethodCallExpr m) {
        String name = m.getNameAsString();
        return name.equals("printStackTrace")
            || ((name.equals("println") || name.equals("print"))
                && m.getScope().map(s -> s.toString().startsWith("System.")).orElse(false));
    }

    private static void add(List<Finding> out, String ruleId, ChangedFile f, Node at, String message) {
        RuleCatalog.Rule rule = RuleCatalog.CODELENS.get(ruleId);
        int line = at.getBegin().map(p -> p.line).orElse(1);
        out.add(new Finding(ruleId, "codelens", rule.category(), rule.severity(), f.path(), line, message));
    }
}
