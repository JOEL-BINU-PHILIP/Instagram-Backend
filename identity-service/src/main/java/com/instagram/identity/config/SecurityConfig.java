package com.instagram.identity.config;

import com.instagram.identity.repository.UserRepository;
import com.instagram.identity.security.CustomUserDetailsService;
import com.instagram.identity.security.JwtAuthenticationFilter;
import com.instagram.identity.security.JwtProvider;
import com.instagram.identity.service.TokenBlacklistService;
import com. instagram.identity.util.CookieUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto. password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org. springframework.security.web.authentication. UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * ✅ HYBRID SECURITY:  Supports both Cookie-based and Bearer token authentication
 *
 * Cookie-based (Web):
 *  - Tokens stored in HttpOnly cookies
 *  - Automatic CSRF protection via SameSite
 *  - Best for web browsers
 *
 * Bearer token (Mobile/API):
 *  - Tokens sent in Authorization header
 *  - Easier for mobile apps and API clients
 *  - Better for Postman testing
 *
 * CSRF:  DISABLED
 *  - Cookie-based auth protected by SameSite attribute
 *  - Bearer tokens don't need CSRF protection
 */
@Configuration
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final TokenBlacklistService blacklistService;
    private final CookieUtil cookieUtil;

    public SecurityConfig(CustomUserDetailsService userDetailsService,
                          PasswordEncoder passwordEncoder,
                          JwtProvider jwtProvider,
                          TokenBlacklistService blacklistService,
                          CookieUtil cookieUtil) {
        this.userDetailsService = userDetailsService;
        this. passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
        this.blacklistService = blacklistService;
        this.cookieUtil = cookieUtil;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * ✅ CORS configuration for cookie-based auth
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of(
                "http://localhost:3000",    // React dev server
                "http://localhost:5173",    // Vite dev server
                "https://yourdomain.com"    // Production
        ));

        config.setAllowCredentials(true);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("Authorization")); // ✅ Expose Bearer token in response

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * ✅ MAIN SECURITY CONFIGURATION
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, UserRepository userRepository) throws Exception {

        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(
                jwtProvider,
                userDetailsService,
                blacklistService,
                cookieUtil,
                userRepository
        );

        http
                // ✅ CSRF disabled - using SameSite cookies + Bearer tokens
                .csrf(csrf -> csrf.disable())

                . cors(cors -> cors.configurationSource(corsConfigurationSource()))

                . sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers(
                                "/auth/register",
                                "/auth/login",
                                "/auth/public-key",
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        ).permitAll()

                        // Authenticated endpoints
                        .requestMatchers("/auth/refresh", "/auth/logout").authenticated()
                        . requestMatchers("/api/user/**").authenticated()

                        // Role-based endpoints
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        . requestMatchers("/moderation/**").hasAnyRole("ADMIN", "MODERATOR")

                        . anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}