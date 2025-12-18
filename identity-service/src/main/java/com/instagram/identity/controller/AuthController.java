package com. instagram.identity.controller;

import com.instagram.identity.model. RefreshToken;
import com.instagram.identity.model.Role;
import com.instagram.identity.model.User;
import com.instagram.identity.dto.LoginRequest;
import com. instagram.identity.dto.RegisterRequest;
import com.instagram. identity.security.JwtProvider;
import com.instagram.identity.service.RefreshTokenService;
import com. instagram.identity.service.TokenBlacklistService;
import com. instagram.identity.service.UserService;
import com. instagram.identity.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework. security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

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
                request.accountType()
        );

        Map<String, String> response = new HashMap<>();
        response.put("message", "User registered successfully");
        response.put("username", user.getUsername());
        return response;
    }

    /**
     * ✅ HYBRID LOGIN
     *
     * Returns:
     *  1. JWT tokens in response body (for Bearer auth)
     *  2. JWT tokens in cookies (for cookie-based auth)
     *
     * Clients can choose which method to use.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest request,
                                                     HttpServletRequest httpRequest,
                                                     HttpServletResponse response) throws Exception {

        // ✅ STEP 1: Fetch user and check account status
        User user = userService. findByUsername(request.username())
                .orElseThrow(() -> new RuntimeException("Invalid username or password"));

        if (user.isSuspended()) {
            String reason = user. getSuspensionReason() != null
                    ? user.getSuspensionReason()
                    : "Your account has been suspended";

            Map<String, Object> error = new HashMap<>();
            error. put("error", "account_suspended");
            error.put("message", reason);

            if (user.getSuspensionExpiresAt() != null) {
                error.put("expiresAt", user.getSuspensionExpiresAt().toString());
            }

            throw new RuntimeException(error.toString());
        }

        if (user.isLoginRestricted()) {
            throw new RuntimeException("Login restricted - please verify your identity via email");
        }

        // ✅ STEP 2:  Authenticate credentials
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // ✅ STEP 3: Generate tokens
        String accessToken = jwtProvider.generateAccessToken(user);

        String ipAddress = getClientIP(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        RefreshToken refreshToken = refreshTokenService.createToken(user, ipAddress, userAgent);

        // ✅ STEP 4: Set cookies (for web browsers)
        response.addCookie(cookieUtil.createAccessTokenCookie(accessToken, 15 * 60));
        response.addCookie(cookieUtil.createRefreshTokenCookie(
                refreshToken.getTokenHash(),
                14 * 24 * 60 * 60
        ));

        // ✅ STEP 5: Record login
        userService.recordLogin(user.getId());

        // ✅ STEP 6: Return tokens in response body (for Bearer auth)
        Map<String, Object> result = new HashMap<>();
        result.put("message", "Login successful");
        result.put("username", user.getUsername());
        result.put("accountType", user.getAccountType().toString());
        result.put("verified", user.isVerified());
        result.put("roles", user.getRoles().stream().map(Role::getName).toList());

        // ✅ Include tokens in response body for mobile/API clients
        result.put("accessToken", accessToken);
        result.put("refreshToken", refreshToken.getTokenHash());
        result.put("expiresIn", 15 * 60); // seconds

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken) // ✅ Also in header
                .body(result);
    }

    /**
     * ✅ HYBRID REFRESH TOKEN
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(HttpServletRequest request,
                                                            HttpServletResponse response) throws Exception {

        // ✅ Try to get refresh token from cookie OR body
        String oldRefreshToken = extractRefreshToken(request);

        if (oldRefreshToken == null) {
            throw new RuntimeException("Refresh token not found");
        }

        // ✅ Rotate token
        RefreshToken newRefreshToken = refreshTokenService. rotateToken(oldRefreshToken);

        User user = userService.findById(newRefreshToken.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        String newAccessToken = jwtProvider.generateAccessToken(user);

        // ✅ Set cookies (for web browsers)
        response.addCookie(cookieUtil. createAccessTokenCookie(newAccessToken, 15 * 60));
        response.addCookie(cookieUtil.createRefreshTokenCookie(
                newRefreshToken.getTokenHash(),
                14 * 24 * 60 * 60
        ));

        // ✅ Return tokens in response body (for mobile/API clients)
        Map<String, Object> result = new HashMap<>();
        result.put("message", "Tokens refreshed successfully");
        result.put("accessToken", newAccessToken);
        result.put("refreshToken", newRefreshToken.getTokenHash());
        result.put("expiresIn", 15 * 60);

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + newAccessToken)
                .body(result);
    }

    /**
     * ✅ HYBRID LOGOUT
     */
    @PostMapping("/logout")
    public Map<String, String> logout(HttpServletRequest request,
                                      HttpServletResponse response) {

        try {
            // ✅ Try cookie first, then Bearer token
            String accessToken = cookieUtil.getAccessToken(request)
                    .or(() -> Optional.ofNullable(extractBearerToken(request)))
                    .orElse(null);

            if (accessToken != null) {
                blacklistService.blacklistToken(
                        accessToken,
                        jwtProvider.getExpiryTimeFromToken(accessToken)
                );
            }

            String refreshToken = extractRefreshToken(request);
            if (refreshToken != null) {
                refreshTokenService.revokeToken(refreshToken);
            }

            // ✅ Delete cookies
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

    /**
     * Helper:  Extract refresh token from cookie OR request body
     */
    private String extractRefreshToken(HttpServletRequest request) {
        // Try cookie first
        Optional<String> cookieToken = cookieUtil.getRefreshToken(request);
        if (cookieToken.isPresent()) {
            return cookieToken.get();
        }

        // Try request body (for mobile clients)
        try {
            String body = request.getReader().lines()
                    .reduce("", (accumulator, actual) -> accumulator + actual);

            // Simple JSON parsing (in production, use Jackson)
            if (body.contains("refreshToken")) {
                return body. split("\"refreshToken\"\\s*:\\s*\"")[1].split("\"")[0];
            }
        } catch (Exception e) {
            // Ignore
        }

        return null;
    }

    /**
     * Helper: Extract Bearer token from Authorization header
     */
    private String extractBearerToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader. substring(7);
        }
        return null;
    }

    /**
     * Helper: Get client IP address
     */
    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null && ! xfHeader.isEmpty()) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    // ✅ Add Optional import at the top
    private java.util.Optional<String> Optional(String s) {
        return java.util.Optional.ofNullable(s);
    }
}