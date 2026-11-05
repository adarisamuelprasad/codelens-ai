package com.codelens.review;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonManagedReference;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.Transient;

@Entity
public class Review {

    public enum Status { QUEUED, RUNNING, DONE, FAILED }

    public enum Trigger { WEBHOOK, MANUAL }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;
    public String repo;
    public int prNumber;
    public String prTitle;
    public String headSha;
    @Enumerated(EnumType.STRING)
    public Trigger triggerSource;
    @Enumerated(EnumType.STRING)
    public Status status;
    public int filesAnalyzed;
    public int filesSkipped;
    public boolean aiUsed;
    public boolean commentPosted;
    public String error;
    public Instant createdAt;
    public Instant finishedAt;
    public Long durationMs;
    /** Set during a run: some files needed Semgrep and it is not installed. Shown in the PR comment only. */
    @Transient
    public boolean semgrepMissing;

    @OneToMany(mappedBy = "review", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("id")
    @JsonManagedReference
    public List<FindingRecord> findings = new ArrayList<>();
}
