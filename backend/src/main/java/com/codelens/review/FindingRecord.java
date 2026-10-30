package com.codelens.review;

import com.codelens.analysis.Finding;
import com.fasterxml.jackson.annotation.JsonBackReference;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/** A stored finding: what the rule said, plus the AI's explanation when there is one. */
@Entity
@Table(name = "finding")
public class FindingRecord {

    public enum Label { CONFIRMED, REJECTED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "review_id")
    @JsonBackReference
    public Review review;

    public String ruleId;
    public String source;
    @Enumerated(EnumType.STRING)
    public Finding.Category category;
    @Enumerated(EnumType.STRING)
    public Finding.Severity severity;
    @Column(name = "file_path")
    public String file;
    public int line;
    public String message;
    public String snippet;
    public String explanation;
    public String suggestedFix;
    public String aiVerdict;
    public String aiVerdictReason;
    @Enumerated(EnumType.STRING)
    public Label humanLabel;

    /** Demoted findings are kept and counted, only shown collapsed. */
    public boolean demoted() {
        return "likely_false_positive".equals(aiVerdict);
    }
}
