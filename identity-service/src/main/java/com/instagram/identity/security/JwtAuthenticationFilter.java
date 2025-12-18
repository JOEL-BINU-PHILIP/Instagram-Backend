package com.instagram.identity.security;

import com.instagram.identity.model.User;
import com.instagram.identity.repository.UserRepository;
import com.instagram.identity.service.TokenBlacklistService;
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
 * ✅ UPGRADED: Now checks suspended users in real-time.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService blacklistService;
    private final CookieUtil cookieUtil;
    private final UserRepository userRepository;  // ✅ ADDED

    /**
     * ✅ FIXED: Constructor now accepts UserRepository.
     */
    public JwtAuthenticationFilter(JwtProvider jwtProvider,
                                   CustomUserDetailsService userDetailsService,
                                   TokenBlacklistService blacklistService,
                                   CookieUtil cookieUtil,
                                   UserRepository userRepository) {  // ✅ ADDED
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
        this.blacklistService = blacklistService;
        this.cookieUtil = cookieUtil;
        this.userRepository = userRepository;  // ✅ ADDED
    }

    /**
     * Skip authentication for public endpoints.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path. startsWith("/auth/register") ||
                path.startsWith("/auth/login") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/v3/api-docs");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            // ✅ Extract JWT from cookie
            String token = cookieUtil.getAccessToken(request).orElse(null);

            if (token != null) {

                // ✅ Check blacklist
                if (blacklistService.isBlacklisted(token)) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Token has been revoked\"}");
                    return;
                }

                // ✅ Validate token
                if (jwtProvider.validateToken(token)) {

                    String username = jwtProvider.getUsernameFromToken(token);
                    var userDetails = userDetailsService.loadUserByUsername(username);

                    // ✅ INSTAGRAM-STYLE: Check if user is suspended
                    Optional<User> userOpt = userRepository.findByUsername(username);

                    if (userOpt. isPresent()) {
                        User user = userOpt.get();

                        if (user.isSuspended()) {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\":\"Account suspended\",\"reason\":\"" +
                                    (user.getSuspensionReason() != null ? user.getSuspensionReason() : "Policy violation") +
                                    "\"}");
                            return;
                        }
                    }

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
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Invalid token\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}