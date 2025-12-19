package com.instagram.post;

import org.springframework.boot.SpringApplication;
import org.springframework. boot.autoconfigure.SpringBootApplication;

/**
 * POST SERVICE
 *
 * Responsibilities:
 *  - Create/update/delete posts
 *  - Like/unlike posts
 *  - Save/unsave posts
 *  - Archive/pin posts
 *  - Manage post visibility
 */
@SpringBootApplication
public class PostServiceApplication {

    public static void main(String[] args) {
        SpringApplication. run(PostServiceApplication.class, args);
        System.out.println("\n✅ Post Service started on port 8083");
    }
}