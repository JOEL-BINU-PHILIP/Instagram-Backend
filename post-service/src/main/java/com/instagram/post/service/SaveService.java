package com.instagram.post.service;

import com.instagram.post.exception.PostNotFoundException;
import com.instagram.post.model.Post;
import com.instagram.post.model.SavedPost;
import com.instagram.post.repository.PostRepository;
import com.instagram.post.repository.SavedPostRepository;
import org. springframework.stereotype.Service;
import org.springframework.transaction.annotation. Transactional;

@Service
public class SaveService {

    private final SavedPostRepository savedPostRepository;
    private final PostRepository postRepository;

    public SaveService(SavedPostRepository savedPostRepository, PostRepository postRepository) {
        this.savedPostRepository = savedPostRepository;
        this.postRepository = postRepository;
    }

    @Transactional
    public void savePost(String postId, String userId, String collectionName) {
        if (savedPostRepository.existsByPostIdAndUserId(postId, userId)) {
            throw new RuntimeException("Post already saved");
        }

        Post post = postRepository.findByIdAndDeletedFalse(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));

        SavedPost savedPost = new SavedPost();
        savedPost.setPostId(postId);
        savedPost.setUserId(userId);
        savedPost.setCollectionName(collectionName);
        savedPostRepository.save(savedPost);

        post.incrementSaves();
        postRepository.save(post);
    }

    @Transactional
    public void unsavePost(String postId, String userId) {
        SavedPost savedPost = savedPostRepository.findByPostIdAndUserId(postId, userId)
                .orElseThrow(() -> new RuntimeException("Saved post not found"));

        savedPostRepository.delete(savedPost);

        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));
        post.decrementSaves();
        postRepository.save(post);
    }

    public boolean isPostSavedByUser(String postId, String userId) {
        if (userId == null) return false;
        return savedPostRepository.existsByPostIdAndUserId(postId, userId);
    }
}