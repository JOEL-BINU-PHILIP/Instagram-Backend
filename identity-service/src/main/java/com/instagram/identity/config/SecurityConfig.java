package com.instagram.identity.config;

import com.instagram.identity.security.CustomUserDetailsService;
import com.instagram.identity.security.JwtAuthenticationFilter;
import com.instagram.identity.security.JwtProvider;
import com.instagram.identity.service.TokenBlacklistService;  // ✅ NEW
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config. Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org. springframework.security.web.authentication. UsernamePasswordAuthenticationFilter;

/**
 * This class configures the entire Spring Security layer.
 *
 * ✅ IMPROVEMENT: Now integrates TokenBlacklistService to reject logged-out tokens.
 */
@Configuration
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final TokenBlacklistService blacklistService;  // ✅ NEW

    public SecurityConfig(CustomUserDetailsService uds,
                          PasswordEncoder passwordEncoder,
                          JwtProvider jwtProvider,
                          TokenBlacklistService blacklistService) {  // ✅ NEW

        this.userDetailsService = uds;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
        this.blacklistService = blacklistService;  // ✅ NEW
    }

    /**
     * This configures how username/password authentication works.
     *
     * Internally, Spring will use:
     *  - our UserDetailsService to fetch users from DB
     *  - our PasswordEncoder to check hashed passwords
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

        provider.setUserDetailsService(userDetailsService); // load user from DB
        provider.setPasswordEncoder(passwordEncoder);       // compare hashed passwords

        return provider;
    }

    /**
     * AuthenticationManager is the main object used during login.
     * Spring automatically wires all authentication providers into it.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config. getAuthenticationManager();
    }

    /**
     * ✅ IMPROVED:  This configures HTTP security with blacklist support.
     *  - disable CSRF (not needed for APIs)
     *  - allow public access to /auth/** endpoints
     *  - require specific roles for admin/buyer/seller routes
     *  - add our JWT filter with blacklist checking
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // ✅ Create JWT filter WITH blacklist service
        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(
                jwtProvider,
                userDetailsService,
                blacklistService  // ✅ NEW:  Now filter checks blacklist
        );

        http
                .csrf(csrf -> csrf. disable())   // APIs don't use CSRF tokens
                .cors(Customizer.withDefaults()) // allow cross-origin requests

                // Make application STATELESS (no server-side sessions)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                . authorizeHttpRequests(auth -> auth
                        // These endpoints DO NOT require authentication
                        .requestMatchers(
                                "/auth/register",
                                "/auth/login",
                                "/auth/refresh",
                                "/auth/logout",
                                "/auth/public-key",
                                "/auth/blacklist/stats",  // ✅ NEW: monitor endpoint
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        ).permitAll()

                        // Role-based access control
                        . requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/seller/**").hasRole("SELLER")
                        .requestMatchers("/buyer/**").hasRole("BUYER")

                        // Any other endpoint MUST be authenticated
                        .anyRequest().authenticated()
                )
                . authenticationProvider(authenticationProvider())

                // Add our JWT filter BEFORE the username/password filter runs
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}