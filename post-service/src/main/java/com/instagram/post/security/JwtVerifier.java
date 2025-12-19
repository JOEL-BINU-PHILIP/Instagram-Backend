package com.instagram.post.security;

import com.instagram.post.config.JwtConfig;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt. SignedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.io. InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security. interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java. util.Base64;
import java.util.Date;

@Component
public class JwtVerifier {

    private final JwtConfig config;
    private RSAPublicKey publicKey;

    public JwtVerifier(JwtConfig config) {
        this.config = config;
    }

    @PostConstruct
    public void loadPublicKey() throws Exception {
        try (InputStream in = getClass().getResourceAsStream(
                config.publicKeyLocation. replace("classpath:", "/"))) {

            if (in == null) {
                throw new RuntimeException("Public key file not found: " + config.publicKeyLocation);
            }

            String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            this.publicKey = loadPublicKey(pem);
        }
    }

    private RSAPublicKey loadPublicKey(String pem) throws Exception {
        String cleaned = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(cleaned);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public boolean validateToken(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);

            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            if (!jwt.verify(verifier)) {
                return false;
            }

            Date exp = jwt.getJWTClaimsSet().getExpirationTime();
            return exp != null && exp.after(new Date());

        } catch (Exception e) {
            return false;
        }
    }

    public String getUserId(String token) {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            throw new RuntimeException("Invalid token");
        }
    }

    public String getUsername(String token) {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            throw new RuntimeException("Invalid token");
        }
    }
}