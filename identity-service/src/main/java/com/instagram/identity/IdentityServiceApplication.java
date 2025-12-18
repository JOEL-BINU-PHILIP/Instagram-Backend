package com.instagram.identity;

import com.instagram.identity.model.Role;
import com.instagram.identity.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
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
public class IdentityServiceApplication implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    public static void main(String[] args) {
        SpringApplication.run(IdentityServiceApplication.class, args);
    }

    @Override
    public void run(String... args) {
        // Ensure required roles exist
        ensureRoleExists("ROLE_USER");
        ensureRoleExists("ROLE_ADMIN");
        ensureRoleExists("ROLE_MODERATOR");
    }

    private void ensureRoleExists(String roleName) {
        if (roleRepository.findByName(roleName).isEmpty()) {
            Role role = new Role();
            role.setName(roleName);
            roleRepository.save(role);
            System.out.println("✅ Created role: " + roleName);
        }
    }
}
