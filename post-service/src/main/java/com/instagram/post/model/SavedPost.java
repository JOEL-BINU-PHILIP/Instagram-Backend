package com.instagram.post.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.Indexed;
import org. springframework.data.mongodb.core. mapping.Document;

import java. time.Instant;

@Data
@Document(collection = "saved_posts")
@CompoundIndex(name = "post_user_idx", def = "{'postId': 1, 'userId': 1}", unique = true)
public class SavedPost {

    @Id
    private String id;

    @Indexed
    private String postId;

    @Indexed
    private String userId;

    private String collectionName;

    private Instant savedAt = Instant.now();
}