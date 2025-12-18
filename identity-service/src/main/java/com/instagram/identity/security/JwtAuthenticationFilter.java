package com.instagram.identity.security;

import com.instagram.identity.service.TokenBlacklistService;
import com.instagram.identity.util.CookieUtil;
import jakarta. servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta. servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * UPGRADED: Now reads JWT from HttpOnly cookies instead of Authorization header.
 *
 * Flow:
 *  1. Extract access token from cookie
 *  2. Check if token is blacklisted
 *  3. Validate token signature and expiry
 *  4. Authenticate user in Spring Security context
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService blacklistService;
    private final CookieUtil cookieUtil;

    public JwtAuthenticationFilter(JwtProvider jwtProvider,
                                   CustomUserDetailsService userDetailsService,
                                   TokenBlacklistService blacklistService,
                                   CookieUtil cookieUtil) {
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
        this.blacklistService = blacklistService;
        this.cookieUtil = cookieUtil;
    }

    /**
     * Skip authentication for public endpoints.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/auth/register") ||
                path.startsWith("/auth/login") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/v3/api-docs");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            // ✅ Extract JWT from cookie (not Authorization header)
            String token = cookieUtil.getAccessToken(request).orElse(null);

            if (token != null) {

                // ✅ Check blacklist first (logged out tokens)
                if (blacklistService.isBlacklisted(token)) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"error\":\"Token has been revoked\"}");
                    return;
                }

                // ✅ Validate token signature and expiry
                if (jwtProvider.validateToken(token)) {

                    String username = jwtProvider.getUsernameFromToken(token);
                    var userDetails = userDetailsService.loadUserByUsername(username);

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
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Invalid token\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}