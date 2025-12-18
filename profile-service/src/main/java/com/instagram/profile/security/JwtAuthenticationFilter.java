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
 * ✅ FIXED: Properly sets UserDetails as principal
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String ACCESS_TOKEN_COOKIE = "access_token";

    private final JwtVerifier jwtVerifier;

    public JwtAuthenticationFilter(JwtVerifier jwtVerifier) {
        this.jwtVerifier = jwtVerifier;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        // Public endpoints don't need authentication
        return path.matches("/profiles/[^/]+") && request.getMethod().equals("GET");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            String token = extractToken(request);

            if (token != null && jwtVerifier.validateToken(token)) {
                String username = jwtVerifier.getUsername(token);

                // ✅ FIXED: Create proper UserDetails object
                UserDetails userDetails = User.builder()
                        .username(username)
                        .password("") // Not used - just for UserDetails interface
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))
                        .build();

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,  // ✅ FIXED:  UserDetails object, not just String
                                null,
                                userDetails.getAuthorities()
                        );

                SecurityContextHolder.getContext().setAuthentication(auth);
            }

        } catch (Exception ex) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    /**
     * ✅ HYBRID: Extract from Bearer header OR cookie
     */
    private String extractToken(HttpServletRequest request) {
        // Try Bearer token first
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        // Fallback to cookie
        if (request.getCookies() != null) {
            return Arrays.stream(request.getCookies())
                    .filter(cookie -> ACCESS_TOKEN_COOKIE.equals(cookie.getName()))
                    . map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }

        return null;
    }
}