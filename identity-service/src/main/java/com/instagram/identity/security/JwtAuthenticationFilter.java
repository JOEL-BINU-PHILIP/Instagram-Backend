package com.instagram.identity.security;

import com.instagram.identity.service.TokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/**
 * This filter runs ONCE per request and checks:
 *  1. Whether an incoming request contains a JWT in the Authorization header
 *  2. If the token is blacklisted (logged out)
 *  3. If valid, authenticate the user inside Spring Security Context
 *
 * IMPROVEMENT: Added blacklist check to prevent logged-out tokens from working.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService blacklistService;

    public JwtAuthenticationFilter(JwtProvider jwtProvider,
                                   CustomUserDetailsService userDetailsService,
                                   TokenBlacklistService blacklistService) {
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
        this.blacklistService = blacklistService;
    }

    /**
     * Skip filtering for public endpoints (login, register, etc.).
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path. startsWith("/auth/register") ||
                path.startsWith("/auth/login") ||
                path.startsWith("/auth/refresh") ||
                path.startsWith("/auth/public-key") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/v3/api-docs");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Read the Authorization header from the incoming request
        String header = request.getHeader("Authorization");

        // Validate that the header exists and contains "Bearer <token>"
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7); // Extract JWT token (remove "Bearer ")

            try {
                // ✅ NEW: Check if token is blacklisted FIRST
                if (blacklistService. isBlacklisted(token)) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Token has been revoked (logged out)");
                    return;
                }

                // Validate the JWT (signature + expiry)
                if (jwtProvider.validateToken(token)) {

                    // Extract username from the token claims
                    String username = jwtProvider.getUsernameFromToken(token);

                    // Load user details from database
                    var userDetails = userDetailsService.loadUserByUsername(username);

                    // Create authentication object with user's roles
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    // Mark the user as authenticated for the current request
                    SecurityContextHolder. getContext().setAuthentication(auth);
                }

            } catch (Exception ex) {
                // If token is invalid, clear any existing authentication
                SecurityContextHolder. clearContext();
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid or expired token");
                return;
            }
        }

        // Continue to the next filter or endpoint handler
        filterChain.doFilter(request, response);
    }
}