package com.codelens.review;

import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingRepository extends JpaRepository<FindingRecord, Long> {}
