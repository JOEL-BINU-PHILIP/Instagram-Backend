package com.instagram.identity.security;

import com.instagram.identity.config.JwtConfig;
import com.instagram.identity.model.Role;
import com.instagram.identity.model.User;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import lombok. Getter;
import org.springframework.stereotype.Component;

import java.io. InputStream;
import java.nio.charset.StandardCharsets;
import java.security. KeyFactory;
import java.security. interfaces.RSAPrivateKey;
import java.security.interfaces. RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java. text.ParseException;
import java. util. Base64;
import java.util. Date;
import java.util. List;
import java.util.stream.Collectors;

/**
 * JwtProvider is responsible for creating and validating JWT tokens.
 *
 * It uses:
 *   - RS256 (asymmetric encryption)
 *   - private_key. pem (to sign tokens)
 *   - public_key.pem  (to verify tokens)
 *
 * IMPROVEMENT: Added helper methods to extract expiry time for blacklist management.
 */
@Component
public class JwtProvider {

    private final JwtConfig config;  // values from application.properties

    private RSAPrivateKey privateKey;  // used to SIGN JWT
    @Getter
    private RSAPublicKey publicKey;    // used to VERIFY JWT

    public JwtProvider(JwtConfig config) {
        this.config = config;
    }

    /**
     * Loads RSA key pair from PEM files during application startup.
     */
    @PostConstruct
    public void loadKeys() throws Exception {

        // -------- Load PRIVATE KEY (used for signing) --------
        try (InputStream in = getClass().getResourceAsStream(
                config.privateKeyLocation. replace("classpath:", "/"))) {

            if (in == null) {
                throw new RuntimeException("Private key file not found:  " + config.privateKeyLocation);
            }

            String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            this.privateKey = loadPrivateKey(pem);
        }

        // -------- Load PUBLIC KEY (used for verification) --------
        try (InputStream in = getClass().getResourceAsStream(
                config.publicKeyLocation. replace("classpath:", "/"))) {

            if (in == null) {
                throw new RuntimeException("Public key file not found: " + config.publicKeyLocation);
            }

            String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            this.publicKey = loadPublicKey(pem);
        }
    }

    /**
     * Converts PEM private key text into a Java RSAPrivateKey object.
     */
    private RSAPrivateKey loadPrivateKey(String pem) throws Exception {
        String cleaned = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", ""); // remove whitespace

        byte[] decoded = Base64.getDecoder().decode(cleaned);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);

        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    /**
     * Converts PEM public key text into a Java RSAPublicKey object.
     */
    private RSAPublicKey loadPublicKey(String pem) throws Exception {
        String cleaned = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(cleaned);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    /**
     * Generates a signed JWT access token for a given user.
     */
    public String generateAccessToken(User user) throws JOSEException {

        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(config.accessTokenValidityMinutes * 60);

        // Create the payload (claims)
        JWTClaimsSet claims = new JWTClaimsSet. Builder()
                .issuer(config.issuer)                         // app name
                .subject(user. getUsername())                  // who the token belongs to
                .issueTime(Date.from(now))                    // token creation time
                .expirationTime(Date.from(expiry))            // token expiry time
                .claim("roles",                               // attach roles inside JWT
                        user.getRoles()
                                .stream()
                                .map(Role::getName)
                                .collect(Collectors.toList()))
                .build();

        // Create JWT header specifying the algorithm (RS256)
        JWSHeader header = new JWSHeader. Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID("jwt-key-1") // optional
                .build();

        // Create signed JWT
        SignedJWT jwt = new SignedJWT(header, claims);

        // Sign with private key
        JWSSigner signer = new RSASSASigner(privateKey);
        jwt.sign(signer);

        return jwt.serialize(); // convert to string
    }

    /**
     * Validates token signature + expiry.
     */
    public boolean validateToken(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);

            // Verify signature using PUBLIC key
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            if (!jwt.verify(verifier)) return false;

            // Check expiration
            Date exp = jwt.getJWTClaimsSet().getExpirationTime();
            return exp != null && exp.after(new Date());

        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Extract the username (subject) from the token.
     */
    public String getUsernameFromToken(String token) {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            throw new RuntimeException("Invalid token");
        }
    }

    /**
     * Extract the roles stored inside the JWT.
     */
    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        try {
            Object rolesObj = SignedJWT. parse(token).getJWTClaimsSet().getClaim("roles");

            if (rolesObj instanceof List<? > list) {
                return (List<String>) list;
            }
            return List.of();

        } catch (ParseException e) {
            return List.of();
        }
    }

    /**
     * NEW: Extract the expiry time from a JWT token.
     * Used by blacklist service to know how long to keep token blacklisted.
     */
    public Instant getExpiryTimeFromToken(String token) {
        try {
            Date expiryDate = SignedJWT.parse(token).getJWTClaimsSet().getExpirationTime();
            return expiryDate != null ? expiryDate.toInstant() : Instant.now();
        } catch (ParseException e) {
            throw new RuntimeException("Invalid token - cannot extract expiry time");
        }
    }

    /**
     * ✅ NEW: Check if token is expired.
     * Useful for additional validation logic.
     */
    public boolean isTokenExpired(String token) {
        try {
            Date expiryDate = SignedJWT.parse(token).getJWTClaimsSet().getExpirationTime();
            return expiryDate != null && expiryDate. before(new Date());
        } catch (ParseException e) {
            return true; // if we can't parse it, consider it expired
        }
    }
}