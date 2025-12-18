package com.instagram.registry. config;

import org.springframework. context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework. security.core.userdetails. UserDetailsService;
import org. springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto. password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * ✅ EUREKA DASHBOARD SECURITY
 *
 * Production recommendation:
 *  - Protect Eureka dashboard with authentication
 *  - Only internal services + admins should access
 *
 * Development:
 *  - Comment out @EnableWebSecurity for easier testing
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Secure Eureka dashboard with basic authentication
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Disable CSRF for service-to-service
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/**").permitAll() // Health checks
                        .anyRequest().authenticated() // Dashboard requires login
                )
                .httpBasic(basic -> {}); // Enable HTTP Basic Auth

        return http.build();
    }

    /**
     * In-memory user for Eureka dashboard access
     *
     * Production:  Use database or LDAP
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
