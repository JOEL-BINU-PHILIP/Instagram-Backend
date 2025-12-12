package com.instagram.identity.controller;

import com.instagram.identity.security.JwtProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Map;

/**
 * This controller exposes the PUBLIC key of the server.
 *
 * Frontend clients use this public key to verify JWT signatures.
 * NOTE: Public key can be shared safely (unlike private key).
 */
@RestController
public class PublicKeyController {

    private final JwtProvider jwtProvider;

    public PublicKeyController(JwtProvider provider) {
        this.jwtProvider = provider;
    }

    /**
     * Returns the public key as a Base64 encoded string.
     */
    @GetMapping("/auth/public-key")
    public Map<String, String> getPublicKey() {

        // Convert public key bytes to Base64 so it can be returned as a string
        String encoded = Base64.getEncoder()
                .encodeToString(jwtProvider.getPublicKey().getEncoded());

        return Map.of("publicKey", encoded);
    }
}

