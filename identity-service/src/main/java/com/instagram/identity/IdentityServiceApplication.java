package com.instagram.identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * This is the main entry point of the Spring Boot application.
 *
 * When you run this class, Spring Boot starts:
 *  - The embedded Tomcat server
 *  - Component scanning (to detect controllers, services, repositories, etc.)
 *  - Auto-configuration for needed components
 */
@SpringBootApplication
public class IdentityServiceApplication {

    public static void main(String[] args) {
        // This starts the entire Spring Boot application.
        SpringApplication.run(IdentityServiceApplication.class, args);
    }
}
