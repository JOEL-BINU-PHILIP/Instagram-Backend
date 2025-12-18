package com.instagram.identity.security;

import com.instagram.identity.model.User;
import com.instagram.identity.repository.UserRepository;
import com.instagram.identity. service.TokenBlacklistService;
import com.instagram.identity.util.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework. security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * ✅ HYBRID JWT Authentication Filter
 *
 * Supports TWO authentication methods:
 *  1. Cookie-based (for web browsers)
 *     - Reads JWT from 'access_token' cookie
 *  2. Bearer token (for mobile/API clients)
 *     - Reads JWT from 'Authorization:  Bearer <token>' header
 *
 * Priority: Bearer token > Cookie
 * (If both present, Bearer token takes precedence)
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService blacklistService;
    private final CookieUtil cookieUtil;
    private final UserRepository userRepository;

    public JwtAuthenticationFilter(JwtProvider jwtProvider,
                                   CustomUserDetailsService userDetailsService,
                                   TokenBlacklistService blacklistService,
                                   CookieUtil cookieUtil,
                                   UserRepository userRepository) {
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
        this.blacklistService = blacklistService;
        this.cookieUtil = cookieUtil;
        this.userRepository = userRepository;
    }

    /**
     * Skip authentication for public endpoints
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/auth/register") ||
                path.startsWith("/auth/login") ||
                path.startsWith("/auth/public-key") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/v3/api-docs");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            // ✅ STEP 1: Extract JWT token (Bearer header OR cookie)
            String token = extractToken(request);

            if (token != null) {

                // ✅ STEP 2: Check blacklist
                if (blacklistService.isBlacklisted(token)) {
                    sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                            "Token has been revoked");
                    return;
                }

                // ✅ STEP 3: Validate token
                if (jwtProvider.validateToken(token)) {

                    String username = jwtProvider.getUsernameFromToken(token);
                    var userDetails = userDetailsService.loadUserByUsername(username);

                    // ✅ STEP 4: Check if user is suspended
                    Optional<User> userOpt = userRepository.findByUsername(username);

                    if (userOpt. isPresent()) {
                        User user = userOpt.get();

                        if (user.isSuspended()) {
                            String reason = user.getSuspensionReason() != null
                                    ? user.getSuspensionReason()
                                    : "Policy violation";
                            sendErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                                    "Account suspended: " + reason);
                            return;
                        }
                    }

                    // ✅ STEP 5: Set authentication in context
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            }

        } catch (Exception ex) {
            SecurityContextHolder.clearContext();
        }

        filterChain. doFilter(request, response);
    }

    /**
     * ✅ HYBRID TOKEN EXTRACTION
     *
     * Priority:
     *  1. Authorization header (Bearer token) - for mobile/API
     *  2. Cookie (access_token) - for web browsers
     */
    private String extractToken(HttpServletRequest request) {
        // Try Bearer token first (mobile/API clients)
        String bearerToken = extractBearerToken(request);
        if (bearerToken != null) {
            return bearerToken;
        }

        // Fallback to cookie (web browsers)
        return cookieUtil.getAccessToken(request).orElse(null);
    }

    /**
     * Extract JWT from Authorization header
     * Format: "Authorization: Bearer <token>"
     */
    private String extractBearerToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader. substring(7); // Remove "Bearer " prefix
        }

        return null;
    }

    /**
     * Helper method to send JSON error responses
     */
    private void sendErrorResponse(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"" + message + "\"}");
    }
}