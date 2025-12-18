package com. instagram.profile.config;

import com.instagram.profile.security.JwtAuthenticationFilter;
import com.instagram.profile.security.JwtVerifier;
import org. springframework.context.annotation.Bean;
import org.springframework.context. annotation.Configuration;
import org. springframework.security.config.annotation. web.builders.HttpSecurity;
import org.springframework.security. config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web. authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * PROFILE SERVICE Security Config
 *
 * Key differences from Identity Service:
 *  - NO CSRF (stateless reads)
 *  - NO password authentication
 *  - ONLY JWT verification
 */
@Configuration
public class SecurityConfig {

    private final JwtVerifier jwtVerifier;

    public SecurityConfig(JwtVerifier jwtVerifier) {
        this.jwtVerifier = jwtVerifier;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000", "https://yourdomain.com"));
        config.setAllowCredentials(true);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtVerifier);

        http
                .csrf(csrf -> csrf.disable()) // Stateless - no CSRF needed
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy. STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        . requestMatchers("/profiles/{username}").permitAll() // Public
                        .requestMatchers("/profiles/me").authenticated()     // Owner only
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}