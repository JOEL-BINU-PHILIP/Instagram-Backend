package com.instagram.post.repository;

import com.instagram.post.model. Post;
import org.springframework. data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface PostRepository extends MongoRepository<Post, String> {

    Optional<Post> findByIdAndDeletedFalse(String id);

    Page<Post> findByUserIdAndDeletedFalseAndArchivedFalse(
            String userId,
            Pageable pageable
    );

    Page<Post> findByUserIdAndArchivedTrueAndDeletedFalse(
            String userId,
            Pageable pageable
    );

    List<Post> findByUserIdAndPinnedTrueAndDeletedFalse(String userId);

    long countByUserIdAndPinnedTrueAndDeletedFalse(String userId);

    Page<Post> findByHashtagsContainingAndDeletedFalse(
            String hashtag,
            Pageable pageable
    );

    Page<Post> findByTaggedUserIdsContainingAndDeletedFalse(
            String userId,
            Pageable pageable
    );

    @Query("{ 'location.name': ?0, 'deleted': false }")
    Page<Post> findByLocationName(String locationName, Pageable pageable);

    long countByUserIdAndDeletedFalseAndArchivedFalse(String userId);

    Page<Post> findByUserIdInAndDeletedFalseAndCreatedAtAfter(
            List<String> userIds,
            Instant since,
            Pageable pageable
    );
}