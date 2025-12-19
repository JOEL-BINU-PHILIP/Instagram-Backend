package com.instagram.post.controller;

import com.instagram.post.dto.*;
import com.instagram.post.service.PostService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security. core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/posts")
@CrossOrigin(origins = "${cors.allowed-origins: http://localhost:3000}", allowCredentials = "true")
public class PostController {

    private final PostService postService;

    public PostController(PostService postService) {
        this.postService = postService;
    }

    @PostMapping
    public ResponseEntity<PostResponse> createPost(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody CreatePostRequest request) {

        String username = userDetails.getUsername();
        String userId = username;

        PostResponse response = postService.createPost(userId, username, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{postId}")
    public ResponseEntity<PostResponse> getPost(
            @PathVariable String postId,
            @AuthenticationPrincipal UserDetails userDetails) {

        String viewerId = userDetails != null ? userDetails.getUsername() : null;
        PostResponse response = postService.getPostById(postId, viewerId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user/{username}")
    public ResponseEntity<Page<PostSummaryResponse>> getUserPosts(
            @PathVariable String username,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "12") int size,
            @AuthenticationPrincipal UserDetails userDetails) {

        String viewerId = userDetails != null ? userDetails.getUsername() : null;
        Page<PostSummaryResponse> response = postService.getUserPosts(username, viewerId, page, size);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/{postId}")
    public ResponseEntity<PostResponse> updatePost(
            @PathVariable String postId,
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody UpdatePostRequest request) {

        String userId = userDetails.getUsername();
        PostResponse response = postService.updatePost(postId, userId, request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{postId}")
    public ResponseEntity<Map<String, String>> deletePost(
            @PathVariable String postId,
            @AuthenticationPrincipal UserDetails userDetails) {

        String userId = userDetails.getUsername();
        postService.deletePost(postId, userId);
        return ResponseEntity. ok(Map.of("message", "Post deleted successfully"));
    }

    @PutMapping("/{postId}/archive")
    public ResponseEntity<Map<String, String>> archivePost(
            @PathVariable String postId,
            @AuthenticationPrincipal UserDetails userDetails) {

        String userId = userDetails.getUsername();
        postService.archivePost(postId, userId);
        return ResponseEntity.ok(Map.of("message", "Post archived"));
    }

    @PutMapping("/{postId}/unarchive")
    public ResponseEntity<Map<String, String>> unarchivePost(
            @PathVariable String postId,
            @AuthenticationPrincipal UserDetails userDetails) {

        String userId = userDetails.getUsername();
        postService.unarchivePost(postId, userId);
        return ResponseEntity.ok(Map.of("message", "Post unarchived"));
    }

    @PutMapping("/{postId}/pin")
    public ResponseEntity<Map<String, String>> pinPost(
            @PathVariable String postId,
            @AuthenticationPrincipal UserDetails userDetails) {

        String userId = userDetails.getUsername();
        postService.pinPost(postId, userId);
        return ResponseEntity.ok(Map.of("message", "Post pinned"));
    }

    @PutMapping("/{postId}/unpin")
    public ResponseEntity<Map<String, String>> unpinPost(
            @PathVariable String postId,
            @AuthenticationPrincipal UserDetails userDetails) {

        String userId = userDetails.getUsername();
        postService.unpinPost(postId, userId);
        return ResponseEntity.ok(Map.of("message", "Post unpinned"));
    }
}