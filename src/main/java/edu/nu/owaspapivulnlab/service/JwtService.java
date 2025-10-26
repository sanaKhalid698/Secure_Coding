package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.ttl-seconds}")
    private long ttlSeconds;

    @Value("${app.jwt.issuer}")
    private String issuer;

    @Value("${app.jwt.audience}")
    private String audience;

    // FIXED(API8): Strong key, added issuer/audience, shorter TTL, and secure signature
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();

        // Generate a secure key from the configured secret
        Key key = Keys.hmacShaKeyFor(secret.getBytes());

        return Jwts.builder()
                .setSubject(subject)
                .setIssuer(issuer)
                .setAudience(audience)
                .addClaims(claims)
                .setIssuedAt(new Date(now))
                // Shorter expiration for better security
                .setExpiration(new Date(now + ttlSeconds * 1000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}
