package com.instagram.post.service;

import com.instagram.post.exception.PostNotFoundException;
import com. instagram.post.model.Like;
import com.instagram.post.model.Post;
import com.instagram.post.repository.LikeRepository;
import com.instagram.post.repository.PostRepository;
import org.springframework. stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class LikeService {

    private final LikeRepository likeRepository;
    private final PostRepository postRepository;

    public LikeService(LikeRepository likeRepository, PostRepository postRepository) {
        this.likeRepository = likeRepository;
        this.postRepository = postRepository;
    }

    @Transactional
    public void likePost(String postId, String userId, String username) {
        if (likeRepository.existsByPostIdAndUserId(postId, userId)) {
            throw new RuntimeException("Post already liked");
        }

        Post post = postRepository. findByIdAndDeletedFalse(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));

        Like like = new Like();
        like.setPostId(postId);
        like.setUserId(userId);
        like.setUsername(username);
        likeRepository.save(like);

        post.incrementLikes();
        postRepository.save(post);
    }

    @Transactional
    public void unlikePost(String postId, String userId) {
        Like like = likeRepository.findByPostIdAndUserId(postId, userId)
                .orElseThrow(() -> new RuntimeException("Like not found"));

        likeRepository.delete(like);

        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));
        post.decrementLikes();
        postRepository.save(post);
    }

    public boolean isPostLikedByUser(String postId, String userId) {
        if (userId == null) return false;
        return likeRepository.existsByPostIdAndUserId(postId, userId);
    }
}