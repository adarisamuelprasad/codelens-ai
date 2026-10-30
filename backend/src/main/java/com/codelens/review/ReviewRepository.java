package com.codelens.review;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ReviewRepository extends JpaRepository<Review, Long> {

    List<Review> findTop50ByOrderByCreatedAtDesc();

    @EntityGraph(attributePaths = "findings")
    Optional<Review> findWithFindingsById(Long id);
}
