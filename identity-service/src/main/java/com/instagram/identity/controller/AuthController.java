package com.instagram.identity.controller;

import com.instagram.identity.dto.AuthResponse;
import com.instagram.identity.dto.LoginRequest;
import com.instagram.identity.dto.RegisterRequest;
import com.instagram.identity.model.RefreshToken;
import com.instagram.identity.model.Role;
import com.instagram.identity.model.User;
import com.instagram.identity.security.JwtProvider;
import com.instagram.identity.service.RefreshTokenService;
import com.instagram.identity.service.TokenBlacklistService;
import com.instagram.identity.service.UserService;
import com.nimbusds.jwt.SignedJWT;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Date;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService blacklistService;  // ✅ NEW
    private final JwtProvider jwtProvider;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserService userService,
                          RefreshTokenService refreshTokenService,
                          TokenBlacklistService blacklistService,  // ✅ NEW
                          JwtProvider jwtProvider,
                          AuthenticationManager authenticationManager,
                          PasswordEncoder passwordEncoder) {

        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.blacklistService = blacklistService;  // ✅ NEW
        this.jwtProvider = jwtProvider;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * REGISTER new user.
     *
     * The request contains username, email, password, and role.
     * This method delegates the work to UserService.
     */
    @PostMapping("/register")
    public User register(@Valid @RequestBody RegisterRequest request) {
        return userService.registerUser(
                request.username(),
                request.email(),
                request.password(),
                request.role()
        );
    }

    /**
     * LOGIN endpoint.
     *
     * Steps:
     * 1. Authenticate username/password using AuthenticationManager
     * 2. If valid, load user info from DB
     * 3. Generate access token + refresh token
     */
    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) throws Exception {

        // This checks username + password
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        // Store authentication in security context for this request
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Fetch user details from DB
        User user = userService.findByUsername(request.username())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Generate tokens
        String jwt = jwtProvider.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createToken(user);

        // Return both tokens + role list
        return new AuthResponse(
                jwt,
                refreshToken. getToken(),
                15 * 60, // expiry in seconds
                user.getRoles().stream().map(Role::getName).toList()
        );
    }

    /**
     * REFRESH ACCESS TOKEN.
     *
     * Client sends refresh token, we:
     * 1. validate it
     * 2. fetch user
     * 3. generate a new access token (JWT)
     */
    @PostMapping("/refresh")
    public AuthResponse refreshToken(@RequestParam String refreshToken) throws Exception {

        // Validate refresh token
        RefreshToken token = refreshTokenService.verifyToken(refreshToken);

        // Find the associated user
        User user = userService.findById(token.getUserId())
                .orElseThrow(() -> new RuntimeException("User no longer exists"));

        // Create a new access token (JWT)
        String newAccessToken = jwtProvider.generateAccessToken(user);

        return new AuthResponse(
                newAccessToken,
                refreshToken, // reuse old refresh token
                15 * 60,
                user.getRoles().stream().map(Role::getName).toList()
        );
    }

    /**
     * ✅ IMPROVED LOGOUT endpoint.
     *
     * Now blacklists BOTH:
     *  1. Access token (JWT) - so it can't be used even if not expired
     *  2. Refresh token - marked as revoked in database
     *
     * This prevents users from continuing to use their old tokens after logout.
     */
    @PostMapping("/logout")
    public String logout(@RequestHeader("Authorization") String authHeader,
                         @RequestParam(required = false) String refreshToken) {

        try {
            // Extract access token from "Bearer <token>"
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String accessToken = authHeader.substring(7);

                // Parse JWT to get expiry time
                SignedJWT jwt = SignedJWT.parse(accessToken);
                Date expiryDate = jwt.getJWTClaimsSet().getExpirationTime();

                // Add access token to blacklist until it naturally expires
                blacklistService.blacklistToken(accessToken, expiryDate. toInstant());
            }

            // Also revoke the refresh token if provided
            if (refreshToken != null && ! refreshToken.isEmpty()) {
                refreshTokenService.revokeToken(refreshToken);
            }

            // Clear Spring Security context
            SecurityContextHolder. clearContext();

            return "Logged out successfully.  Both access and refresh tokens have been revoked.";

        } catch (Exception e) {
            return "Logout completed (token validation failed, but context cleared)";
        }
    }

    /**
     * ✅ NEW:  Health check endpoint to monitor blacklist size.
     * Useful for debugging and monitoring in production.
     */
    @GetMapping("/blacklist/stats")
    public String getBlacklistStats() {
        return "Blacklisted tokens count: " + blacklistService.getBlacklistSize();
    }
}