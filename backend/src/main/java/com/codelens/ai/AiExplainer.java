package com.codelens.ai;

import java.util.List;
import java.util.Map;

/** The Python ai-service, seen from here. */
public interface AiExplainer {

    /** One finding to explain; {@code language} is CodeLens's name for the file's language (python, go...). */
    record Item(String id, String ruleId, String category, String severity, String message,
                String ruleDescription, String file, int line, String snippet, String language) {}

    record Explanation(String explanation, String suggestedFix, String verdict, String verdictReason) {}

    boolean enabled();

    /** Results by item id. Empty when the service is off or failed: findings then keep the rule's own message. */
    Map<String, Explanation> explain(String repo, String prTitle, List<Item> items);
}
