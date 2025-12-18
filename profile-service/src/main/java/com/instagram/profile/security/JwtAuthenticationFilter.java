package com.instagram.profile.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework. web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * ✅ COMPLETE JWT Authentication Filter for Profile Service
 *
 * Features:
 *  - Hybrid auth: Bearer token OR Cookie
 *  - Proper handling of /profiles/me vs /profiles/{username}
 *  - Public profile views don't require authentication
 *  - All other endpoints require authentication
 *
 * Authentication Flow:
 *  1. Extract JWT from Authorization header or cookie
 *  2. Validate JWT signature and expiration
 *  3. Extract username from JWT
 *  4. Create UserDetails and set in SecurityContext
 *  5. Controller can access via @AuthenticationPrincipal
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String ACCESS_TOKEN_COOKIE = "access_token";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtVerifier jwtVerifier;

    public JwtAuthenticationFilter(JwtVerifier jwtVerifier) {
        this.jwtVerifier = jwtVerifier;
    }

    /**
     * ✅ FIXED: Determines which requests should skip JWT authentication
     *
     * Public endpoints (no auth required):
     *  - GET /profiles/{username} (view any user's profile)
     *
     * Protected endpoints (auth required):
     *  - GET /profiles/me (view own profile)
     *  - PUT /profiles/me (update own profile)
     *  - All other requests
     *
     * @return true if request should skip authentication, false otherwise
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        String method = request.getMethod();

        // ✅ CRITICAL:  /profiles/me must ALWAYS require authentication
        if (path.equals("/profiles/me")) {
            return false; // DO NOT skip - requires auth
        }

        // ✅ Public endpoint: GET /profiles/{username}
        // Allows viewing other users' profiles without login
        if (method.equals("GET") && path.matches("/profiles/[^/]+")) {
            return true; // Skip auth - public endpoint
        }

        // ✅ All other requests require authentication
        return false;
    }

    /**
     * ✅ Main filter logic:  Extract and validate JWT, set authentication
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            // ✅ STEP 1: Extract JWT token (Bearer header OR cookie)
            String token = extractToken(request);

            if (token != null) {

                // ✅ STEP 2: Validate token signature and expiration
                if (jwtVerifier.validateToken(token)) {

                    // ✅ STEP 3: Extract username from JWT
                    String username = jwtVerifier.getUsername(token);

                    // ✅ STEP 4: Create Spring Security UserDetails object
                    UserDetails userDetails = User. builder()
                            .username(username)
                            .password("") // Not used - Profile Service doesn't handle passwords
                            .authorities(new SimpleGrantedAuthority("ROLE_USER"))
                            .build();

                    // ✅ STEP 5: Create authentication token
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,  // Principal (can be accessed in controller)
                                    null,         // Credentials (not needed)
                                    userDetails.getAuthorities()  // Roles
                            );

                    // ✅ STEP 6: Set authentication in SecurityContext
                    // This makes it available to @AuthenticationPrincipal in controllers
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }

        } catch (Exception ex) {
            // ✅ On any error, clear authentication
            // Request will proceed as unauthenticated
            SecurityContextHolder.clearContext();

            // Optional: Log the error for debugging
            // logger.debug("JWT authentication failed: {}", ex.getMessage());
        }

        // ✅ Continue filter chain
        filterChain. doFilter(request, response);
    }

    /**
     * ✅ HYBRID TOKEN EXTRACTION
     *
     * Supports two authentication methods:
     *  1. Bearer token in Authorization header (for mobile apps, API clients)
     *  2. JWT in HttpOnly cookie (for web browsers)
     *
     * Priority: Bearer token > Cookie
     * (If both present, Bearer token takes precedence)
     *
     * @return JWT token string, or null if not found
     */
    private String extractToken(HttpServletRequest request) {
        // ✅ PRIORITY 1: Try Bearer token from Authorization header
        String bearerToken = extractBearerToken(request);
        if (bearerToken != null) {
            return bearerToken;
        }

        // ✅ PRIORITY 2: Try JWT from cookie
        return extractCookieToken(request);
    }

    /**
     * Extract JWT from Authorization header
     *
     * Expected format: "Authorization: Bearer eyJhbGciOi..."
     *
     * @return JWT token without "Bearer " prefix, or null if not found/invalid
     */
    private String extractBearerToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length()).trim();
        }

        return null;
    }

    /**
     * Extract JWT from HttpOnly cookie
     *
     * Cookie name: "access_token"
     * Set by Identity Service during login
     *
     * @return JWT token from cookie, or null if not found
     */
    private String extractCookieToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return null;
        }

        return Arrays.stream(cookies)
                .filter(cookie -> ACCESS_TOKEN_COOKIE.equals(cookie. getName()))
                .map(Cookie::getValue)
                .filter(value -> value != null && ! value.isEmpty())
                .findFirst()
                .orElse(null);
    }
}