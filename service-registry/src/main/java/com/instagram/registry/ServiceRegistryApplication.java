package com.instagram.registry;

import org.springframework. boot.SpringApplication;
import org.springframework.boot.autoconfigure. SpringBootApplication;
import org. springframework.cloud.netflix.eureka.server.EnableEurekaServer;

/**
 * EUREKA SERVICE REGISTRY
 *
 * Responsibilities:
 *  - Service Discovery:  Track all running microservices
 *  - Health Monitoring: Detect failed services
 *  - Load Balancing: Help API Gateway distribute requests
 *  - Dynamic Scaling: Auto-detect new service instances
 *
 * Why Eureka? 
 *  - Self-healing: Auto-removes dead services
 *  - Zero-config: Services auto-register on startup
 *  - Netflix-proven: Used in production at massive scale
 *
 * Access Dashboard: 
 *  - URL: http://localhost:8761
 *  - Shows all registered services, health status, metadata
 */
@SpringBootApplication
@EnableEurekaServer  // This makes it a Eureka Server
public class ServiceRegistryApplication {

    public static void main(String[] args) {
        SpringApplication. run(ServiceRegistryApplication.class, args);
        System.out.println("\nService Registry started successfully!");
        System.out.println("Eureka Dashboard: http://localhost:8761");
        System.out.println("Waiting for services to register...\n");
    }
}
