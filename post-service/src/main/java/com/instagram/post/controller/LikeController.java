package com.instagram.post. controller;

import com.instagram. post.service.LikeService;
import org.springframework.http.ResponseEntity;
import org.springframework. security.core.annotation.AuthenticationPrincipal;
import org. springframework.security.core.userdetails.UserDetails;
import org.springframework. web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/posts/{postId}/likes")
@CrossOrigin(origins = "${cors.allowed-origins:http://localhost:3000}", allowCredentials = "true")
public class LikeController {

    private final LikeService likeService;

    public LikeController(LikeService likeService) {
        this.likeService = likeService;
    }

    @PostMapping
    public ResponseEntity<Map<String, String>> likePost(
            @PathVariable String postId,
            @AuthenticationPrincipal UserDetails userDetails) {

        String username = userDetails.getUsername();
        String userId = username;

        likeService.likePost(postId, userId, username);
        return ResponseEntity.ok(Map.of("message", "Post liked"));
    }

    @DeleteMapping
    public ResponseEntity<Map<String, String>> unlikePost(
            @PathVariable String postId,
            @AuthenticationPrincipal UserDetails userDetails) {

        String userId = userDetails.getUsername();
        likeService.unlikePost(postId, userId);
        return ResponseEntity.ok(Map. of("message", "Post unliked"));
    }
}