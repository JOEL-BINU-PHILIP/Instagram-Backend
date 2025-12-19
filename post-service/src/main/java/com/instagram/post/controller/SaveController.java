package com.instagram.post.controller;

import com.instagram.post. service.SaveService;
import org.springframework.http.ResponseEntity;
import org.springframework.security. core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org. springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/posts/{postId}/saves")
@CrossOrigin(origins = "${cors.allowed-origins:http://localhost:3000}", allowCredentials = "true")
public class SaveController {

    private final SaveService saveService;

    public SaveController(SaveService saveService) {
        this.saveService = saveService;
    }

    @PostMapping
    public ResponseEntity<Map<String, String>> savePost(
            @PathVariable String postId,
            @RequestParam(required = false) String collection,
            @AuthenticationPrincipal UserDetails userDetails) {

        String userId = userDetails.getUsername();
        saveService.savePost(postId, userId, collection);
        return ResponseEntity.ok(Map.of("message", "Post saved"));
    }

    @DeleteMapping
    public ResponseEntity<Map<String, String>> unsavePost(
            @PathVariable String postId,
            @AuthenticationPrincipal UserDetails userDetails) {

        String userId = userDetails. getUsername();
        saveService. unsavePost(postId, userId);
        return ResponseEntity.ok(Map.of("message", "Post unsaved"));
    }
}