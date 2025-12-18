package com.instagram.identity.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta. servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

/**
 * Utility class for managing secure HttpOnly cookies.
 *
 * Instagram-style approach:
 *  - Access token stored in HttpOnly cookie (cannot be read by JavaScript)
 *  - Refresh token stored in separate HttpOnly cookie
 *  - Both use Secure flag (HTTPS only in production)
 *  - SameSite=None for cross-origin requests (mobile apps, SPAs)
 */
@Component
public class CookieUtil {

    // Cookie names
    public static final String ACCESS_TOKEN_COOKIE = "access_token";
    public static final String REFRESH_TOKEN_COOKIE = "refresh_token";

    @Value("${cookie.domain:localhost}")
    private String cookieDomain;

    @Value("${cookie.secure:false}") // Set to true in production with HTTPS
    private boolean secure;

    /**
     * Creates an HttpOnly cookie for the access token.
     *
     * Security properties:
     *  - HttpOnly: Prevents XSS attacks (JavaScript cannot read it)
     *  - Secure: Only sent over HTTPS (set false for local development)
     *  - SameSite=None: Required for cross-origin requests
     *  - Path=/: Available to all endpoints
     */
    public Cookie createAccessTokenCookie(String token, int maxAgeSeconds) {
        Cookie cookie = new Cookie(ACCESS_TOKEN_COOKIE, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);  // HTTPS only (in production)
        cookie.setPath("/");
        cookie.setMaxAge(maxAgeSeconds);
        cookie.setAttribute("SameSite", "None"); // Cross-origin support

        // Only set domain in production (not localhost)
        if (!cookieDomain.equals("localhost")) {
            cookie.setDomain(cookieDomain);
        }

        return cookie;
    }

    /**
     * Creates an HttpOnly cookie for the refresh token.
     *
     * Refresh tokens live longer (14 days) but are rotated on each use.
     */
    public Cookie createRefreshTokenCookie(String token, int maxAgeSeconds) {
        Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/auth/refresh"); // ✅ Only sent to refresh endpoint
        cookie.setMaxAge(maxAgeSeconds);
        cookie.setAttribute("SameSite", "None");

        if (!cookieDomain.equals("localhost")) {
            cookie.setDomain(cookieDomain);
        }

        return cookie;
    }

    /**
     * Deletes a cookie by setting MaxAge=0.
     * Used during logout.
     */
    public Cookie deleteCookie(String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath(cookieName. equals(REFRESH_TOKEN_COOKIE) ? "/auth/refresh" : "/");
        cookie.setMaxAge(0); // ✅ Immediate deletion
        cookie.setAttribute("SameSite", "None");

        if (!cookieDomain.equals("localhost")) {
            cookie.setDomain(cookieDomain);
        }

        return cookie;
    }

    /**
     * Extracts a cookie value from the request.
     * Returns Optional.empty() if cookie not found.
     */
    public Optional<String> getCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) {
            return Optional. empty();
        }

        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }

    /**
     * Extracts access token from request cookies.
     */
    public Optional<String> getAccessToken(HttpServletRequest request) {
        return getCookieValue(request, ACCESS_TOKEN_COOKIE);
    }

    /**
     * Extracts refresh token from request cookies.
     */
    public Optional<String> getRefreshToken(HttpServletRequest request) {
        return getCookieValue(request, REFRESH_TOKEN_COOKIE);
    }
}