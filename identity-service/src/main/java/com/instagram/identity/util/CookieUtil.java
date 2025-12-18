package com.instagram.identity.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

/**
 * ✅ UPDATED:  Added SameSite attribute for CSRF protection
 */
@Component
public class CookieUtil {

    public static final String ACCESS_TOKEN_COOKIE = "access_token";
    public static final String REFRESH_TOKEN_COOKIE = "refresh_token";

    @Value("${cookie.domain:localhost}")
    private String cookieDomain;

    @Value("${cookie.secure:false}")
    private boolean secure;

    /**
     * ✅ Creates HttpOnly cookie with SameSite protection
     */
    public Cookie createAccessTokenCookie(String token, int maxAgeSeconds) {
        Cookie cookie = new Cookie(ACCESS_TOKEN_COOKIE, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAgeSeconds);

        // ✅ SameSite=Lax prevents CSRF attacks
        cookie.setAttribute("SameSite", "Lax");

        if (! cookieDomain.equals("localhost")) {
            cookie. setDomain(cookieDomain);
        }

        return cookie;
    }

    /**
     * ✅ Refresh token with stricter SameSite
     */
    public Cookie createRefreshTokenCookie(String token, int maxAgeSeconds) {
        Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/auth/refresh");
        cookie.setMaxAge(maxAgeSeconds);

        // ✅ SameSite=Strict for refresh tokens (more secure)
        cookie.setAttribute("SameSite", "Strict");

        if (!cookieDomain.equals("localhost")) {
            cookie.setDomain(cookieDomain);
        }

        return cookie;
    }

    /**
     * Delete cookie
     */
    public Cookie deleteCookie(String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath(cookieName. equals(REFRESH_TOKEN_COOKIE) ? "/auth/refresh" : "/");
        cookie.setMaxAge(0);
        cookie.setAttribute("SameSite", "Lax");

        if (!cookieDomain.equals("localhost")) {
            cookie.setDomain(cookieDomain);
        }

        return cookie;
    }

    /**
     * Extract cookie value
     */
    public Optional<String> getCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) {
            return Optional. empty();
        }

        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .map(Cookie:: getValue)
                .findFirst();
    }

    public Optional<String> getAccessToken(HttpServletRequest request) {
        return getCookieValue(request, ACCESS_TOKEN_COOKIE);
    }

    public Optional<String> getRefreshToken(HttpServletRequest request) {
        return getCookieValue(request, REFRESH_TOKEN_COOKIE);
    }
}