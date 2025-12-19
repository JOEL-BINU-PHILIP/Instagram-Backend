package com.instagram.post. repository;

import com.instagram. post.model.Like;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface LikeRepository extends MongoRepository<Like, String> {

    boolean existsByPostIdAndUserId(String postId, String userId);

    Optional<Like> findByPostIdAndUserId(String postId, String userId);

    long countByPostId(String postId);

    Page<Like> findByPostId(String postId, Pageable pageable);

    Page<Like> findByUserId(String userId, Pageable pageable);

    void deleteAllByPostId(String postId);
}