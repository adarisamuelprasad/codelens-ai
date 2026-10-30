package com.codelens.analysis;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.codelens.diff.ChangedFile;

import net.sourceforge.pmd.PMDConfiguration;
import net.sourceforge.pmd.PmdAnalysis;
import net.sourceforge.pmd.lang.LanguageRegistry;
import net.sourceforge.pmd.lang.document.FileId;
import net.sourceforge.pmd.reporting.Report;
import net.sourceforge.pmd.reporting.RuleViolation;

// Runs the curated ruleset (rulesets/codelens.xml) over PR files held in
// memory. There is no checkout and no classpath, so PMD's type resolution is
// partial; the rules chosen still work on source alone.
@Component
public class PmdAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(PmdAnalyzer.class);

    public List<Finding> analyze(List<ChangedFile> files) {
        PMDConfiguration config = new PMDConfiguration();
        config.setDefaultLanguageVersion(LanguageRegistry.PMD.getLanguageById("java").getVersion("17"));
        config.addRuleSet("rulesets/codelens.xml");
        config.setIgnoreIncrementalAnalysis(true);

        List<Finding> out = new ArrayList<>();
        try (PmdAnalysis pmd = PmdAnalysis.create(config)) {
            for (ChangedFile f : files) {
                pmd.files().addSourceFile(FileId.fromPathLikeString(f.path()), f.content());
            }
            Report report = pmd.performAnalysisAndCollectReport();
            for (RuleViolation v : report.getViolations()) {
                String ruleId = v.getRule().getName();
                RuleCatalog.Rule rule = RuleCatalog.PMD.get(ruleId);
                if (rule == null) continue; // not ours; cannot happen while the ruleset and catalog agree
                out.add(new Finding(ruleId, "pmd", rule.category(), rule.severity(),
                    v.getFileId().getOriginalPath(), v.getBeginLine(), v.getDescription()));
            }
            if (!report.getProcessingErrors().isEmpty()) {
                log.info("PMD could not parse {} file(s)", report.getProcessingErrors().size());
            }
        }
        return out;
    }
}
