package com.instagram.post.repository;

import com.instagram.post.model.SavedPost;
import org.springframework.data.domain.Page;
import org.springframework.data.domain. Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface SavedPostRepository extends MongoRepository<SavedPost, String> {

    boolean existsByPostIdAndUserId(String postId, String userId);

    Optional<SavedPost> findByPostIdAndUserId(String postId, String userId);

    Page<SavedPost> findByUserId(String userId, Pageable pageable);

    Page<SavedPost> findByUserIdAndCollectionName(
            String userId,
            String collectionName,
            Pageable pageable
    );

    long countByUserId(String userId);

    void deleteAllByPostId(String postId);
}