package com.instagram.identity.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework. security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Forces Spring Security to generate a CSRF token on every request.
 *
 * Why needed:
 *  - CookieCsrfTokenRepository is LAZY by default
 *  - It only creates the cookie when a state-changing request happens
 *  - We need the CSRF cookie available BEFORE the first POST request
 *  - This filter forces token generation on first GET request
 *
 * Instagram approach:
 *  - CSRF token stored in readable cookie (XSRF-TOKEN)
 *  - Frontend reads it and sends via X-CSRF-TOKEN header
 *  - Protects against CSRF attacks while using cookies
 */
public class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Force Spring Security to generate CSRF token
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class. getName());

        if (csrfToken != null) {
            // Trigger token generation by calling getToken()
            csrfToken.getToken();
        }

        filterChain. doFilter(request, response);
    }
}