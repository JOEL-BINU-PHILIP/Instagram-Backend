package com.instagram.identity.config;

import com.instagram.identity.security.CsrfCookieFilter;
import com. instagram.identity.security.CustomUserDetailsService;
import com. instagram.identity.security.JwtAuthenticationFilter;
import com. instagram.identity.security.JwtProvider;
import com.instagram. identity.service.TokenBlacklistService;
import com.instagram.identity.util.CookieUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config. Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto. password. PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework. security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security. web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * UPGRADED: Instagram-style security configuration.
 *
 * Key changes:
 *  1. CSRF protection enabled (cookie-based)
 *  2.  CORS configured for credentials (cookies)
 *  3. JWT filter reads from cookies
 *  4. Stateless session management preserved
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
        return config. getAuthenticationManager();
    }

    /**
     * ✅ CORS configuration that allows credentials (cookies).
     *
     * CRITICAL for cookie-based auth:
     *  - allowCredentials = true
     *  - allowedOrigins must be specific (cannot use "*")
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // ✅ Allow specific origins (NOT "*" when using credentials)
        config.setAllowedOrigins(List.of("http://localhost:3000", "https://yourdomain.com"));

        // ✅ CRITICAL: Required for cookies to work cross-origin
        config.setAllowCredentials(true);

        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("X-CSRF-TOKEN"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * ✅ MAIN SECURITY CONFIGURATION
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // ✅ Create JWT filter with cookie support
        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(
                jwtProvider,
                userDetailsService,
                blacklistService,
                cookieUtil
        );

        // ✅ CSRF configuration (Instagram-style)
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName("_csrf");

        http
                // ✅ ENABLE CSRF with cookie-based tokens
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        . csrfTokenRequestHandler(requestHandler)
                        // ✅ Disable CSRF ONLY for login/register (stateless operations)
                        .ignoringRequestMatchers(
                                "/auth/login",
                                "/auth/register",
                                "/auth/public-key",
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        )
                )

                // ✅ CORS with credentials support
                .cors(cors -> cors. configurationSource(corsConfigurationSource()))

                // ✅ Stateless sessions (JWT-based)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy. STATELESS)
                )

                // ✅ Authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers(
                                "/auth/register",
                                "/auth/login",
                                "/auth/public-key",
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        ).permitAll()

                        // Protected endpoints (require CSRF token)
                        .requestMatchers("/auth/refresh", "/auth/logout").authenticated()

                        // Role-based access
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/seller/**").hasRole("SELLER")
                        .requestMatchers("/buyer/**").hasRole("BUYER")

                        . anyRequest().authenticated()
                )

                . authenticationProvider(authenticationProvider())

                // Add CSRF cookie filter BEFORE Spring Security's CSRF filter
                .addFilterBefore(new CsrfCookieFilter(),
                        org.springframework.security.web.csrf.CsrfFilter.class)

                // Add JWT filter
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}