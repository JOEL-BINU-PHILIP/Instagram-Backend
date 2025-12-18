package com.instagram.identity.controller;

import com.instagram.identity.model.RefreshToken;
import com.instagram.identity.model.Role;
import com.instagram.identity.model.User;
import com.instagram.identity.dto.LoginRequest;
import com.instagram. identity.dto.RegisterRequest;
import com.instagram. identity.security.JwtProvider;
import com.instagram.identity.service.RefreshTokenService;
import com.instagram.identity. service.TokenBlacklistService;
import com. instagram.identity.service.UserService;
import com.instagram.identity.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "${cors.allowed-origins: http://localhost:3000}", allowCredentials = "true")
public class AuthController {

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService blacklistService;
    private final JwtProvider jwtProvider;
    private final AuthenticationManager authenticationManager;
    private final CookieUtil cookieUtil;

    public AuthController(UserService userService,
                          RefreshTokenService refreshTokenService,
                          TokenBlacklistService blacklistService,
                          JwtProvider jwtProvider,
                          AuthenticationManager authenticationManager,
                          CookieUtil cookieUtil) {
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.blacklistService = blacklistService;
        this.jwtProvider = jwtProvider;
        this.authenticationManager = authenticationManager;
        this.cookieUtil = cookieUtil;
    }

    @PostMapping("/register")
    public Map<String, String> register(@Valid @RequestBody RegisterRequest request) {
        User user = userService.registerUser(
                request.username(),
                request.email(),
                request.password(),
                request. role()
        );

        Map<String, String> response = new HashMap<>();
        response.put("message", "User registered successfully");
        response.put("username", user.getUsername());
        return response;
    }

    /**
     * ✅ FIXED: Use getTokenHash() instead of getToken()
     */
    @PostMapping("/login")
    public Map<String, Object> login(@Valid @RequestBody LoginRequest request,
                                     HttpServletRequest httpRequest,
                                     HttpServletResponse response) throws Exception {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = userService.findByUsername(request.username())
                .orElseThrow(() -> new RuntimeException("User not found"));

        String accessToken = jwtProvider.generateAccessToken(user);

        // ✅ Get client metadata
        String ipAddress = getClientIP(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        // ✅ Create refresh token with tracking
        RefreshToken refreshToken = refreshTokenService.createToken(user, ipAddress, userAgent);

        // ✅ FIXED: Use getTokenHash() - service returns raw token here
        response.addCookie(cookieUtil.createAccessTokenCookie(accessToken, 15 * 60));
        response.addCookie(cookieUtil.createRefreshTokenCookie(
                refreshToken.getTokenHash(),  // ✅ FIXED - contains raw token
                14 * 24 * 60 * 60
        ));

        Map<String, Object> result = new HashMap<>();
        result.put("message", "Login successful");
        result.put("username", user.getUsername());
        result.put("roles", user.getRoles().stream().map(Role::getName).toList());

        return result;
    }

    /**
     * ✅ FIXED: Use getTokenHash() instead of getToken()
     */
    @PostMapping("/refresh")
    public Map<String, String> refreshToken(HttpServletRequest request,
                                            HttpServletResponse response) throws Exception {

        String oldRefreshToken = cookieUtil.getRefreshToken(request)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        // ✅ Rotate token (validates and creates new one)
        RefreshToken newRefreshToken = refreshTokenService.rotateToken(oldRefreshToken);

        User user = userService.findById(newRefreshToken.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        String newAccessToken = jwtProvider. generateAccessToken(user);

        // ✅ FIXED: Use getTokenHash() - service returns raw token here
        response.addCookie(cookieUtil.createAccessTokenCookie(newAccessToken, 15 * 60));
        response.addCookie(cookieUtil.createRefreshTokenCookie(
                newRefreshToken.getTokenHash(),  // ✅ FIXED - contains raw token
                14 * 24 * 60 * 60
        ));

        Map<String, String> result = new HashMap<>();
        result.put("message", "Tokens refreshed successfully");
        return result;
    }

    @PostMapping("/logout")
    public Map<String, String> logout(HttpServletRequest request,
                                      HttpServletResponse response) {

        try {
            cookieUtil.getAccessToken(request).ifPresent(accessToken -> {
                try {
                    blacklistService.blacklistToken(
                            accessToken,
                            jwtProvider.getExpiryTimeFromToken(accessToken)
                    );
                } catch (Exception e) {
                    // Continue logout even if blacklist fails
                }
            });

            cookieUtil.getRefreshToken(request).ifPresent(refreshTokenService::revokeToken);

            response.addCookie(cookieUtil.deleteCookie(CookieUtil.ACCESS_TOKEN_COOKIE));
            response.addCookie(cookieUtil.deleteCookie(CookieUtil.REFRESH_TOKEN_COOKIE));

            SecurityContextHolder.clearContext();

        } catch (Exception e) {
            // Continue with logout
        }

        Map<String, String> result = new HashMap<>();
        result.put("message", "Logged out successfully");
        return result;
    }

    @GetMapping("/blacklist/stats")
    public Map<String, Object> getBlacklistStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("blacklistedTokens", blacklistService. getBlacklistSize());
        stats.put("message", "Token blacklist statistics");
        return stats;
    }

    /**
     * ✅ Helper method to extract real client IP
     */
    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isEmpty()) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}