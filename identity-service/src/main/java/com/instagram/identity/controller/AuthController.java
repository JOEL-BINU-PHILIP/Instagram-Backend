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
                request.fullName(),
                request.accountType()  // This can be null, defaults to PERSONAL
        );

        Map<String, String> response = new HashMap<>();
        response.put("message", "User registered successfully");
        response.put("username", user.getUsername());
        return response;
    }

    /**
     * ✅ INSTAGRAM-STYLE LOGIN
     *
     * Changes:
     *  1. Reject suspended users BEFORE issuing tokens
     *  2. Reject login-restricted users
     *  3. Record last login timestamp
     *  4. Return suspension reason if applicable
     */
    @PostMapping("/login")
    public Map<String, Object> login(@Valid @RequestBody LoginRequest request,
                                     HttpServletRequest httpRequest,
                                     HttpServletResponse response) throws Exception {

        // ✅ STEP 1: Fetch user first to check flags
        User user = userService. findByUsername(request.username())
                .orElseThrow(() -> new RuntimeException("Invalid username or password"));

        // ✅ STEP 2: Check if user CAN authenticate
        if (user.isSuspended()) {
            String reason = user.getSuspensionReason() != null
                    ? user.getSuspensionReason()
                    : "Your account has been suspended";

            Map<String, Object> error = new HashMap<>();
            error.put("error", "account_suspended");
            error.put("message", reason);

            if (user.getSuspensionExpiresAt() != null) {
                error. put("expiresAt", user.getSuspensionExpiresAt().toString());
            }

            throw new RuntimeException(error.toString());
        }

        if (user.isLoginRestricted()) {
            throw new RuntimeException("Login restricted - please verify your identity via email");
        }

        // ✅ STEP 3: NOW authenticate credentials
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // ✅ STEP 4: Generate tokens
        String accessToken = jwtProvider.generateAccessToken(user);

        String ipAddress = getClientIP(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        RefreshToken refreshToken = refreshTokenService.createToken(user, ipAddress, userAgent);

        response.addCookie(cookieUtil.createAccessTokenCookie(accessToken, 15 * 60));
        response.addCookie(cookieUtil.createRefreshTokenCookie(
                refreshToken.getTokenHash(),
                14 * 24 * 60 * 60
        ));

        // ✅ STEP 5: Record login
        userService.recordLogin(user.getId());

        // ✅ STEP 6: Return user info
        Map<String, Object> result = new HashMap<>();
        result.put("message", "Login successful");
        result.put("username", user.getUsername());
        result.put("accountType", user.getAccountType().toString());
        result.put("verified", user.isVerified());
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