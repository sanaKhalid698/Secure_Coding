package edu.nu.owaspapivulnlab.web;

import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);

    private final ConcurrentHashMap<String, AtomicInteger> failedAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> lockoutUntil = new ConcurrentHashMap<>();

    public AuthController(AppUserRepository users, JwtService jwt) {
        this.users = users;
        this.jwt = jwt;
    }

    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() { return username; }
        public String getPassword() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;

        public TokenRes() {}

        public TokenRes(String token) {
            this.token = token;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        String username = Optional.ofNullable(req.getUsername()).orElse("").trim().toLowerCase();

        // Check lockout
        Instant until = lockoutUntil.get(username);
        if (until != null && Instant.now().isBefore(until)) {
            Map<String, String> locked = new HashMap<>();
            locked.put("error", "Too many failed attempts. Try again later.");
            return ResponseEntity.status(429).body(locked); // 429 Too Many Requests
        }

        AppUser user = users.findByUsername(username).orElse(null);

        // If user exists, verify password using BCrypt hashed comparison.
        // If user does not exist, perform a fake BCrypt check to make timing similar (mitigate user enumeration/timing attacks).
        boolean passwordMatches = false;
        if (user != null) {
            // stored password must be a bcrypt hash (ensure user registration hashes passwords)
            passwordMatches = passwordEncoder.matches(req.getPassword(), user.getPassword());
        } else {
            // Fake hashing to equalize response time and avoid revealing valid usernames
            passwordEncoder.matches(req.getPassword() + "fakeSalt", "$2a$10$......................................");
            passwordMatches = false;
        }

        if (user != null && passwordMatches) {
            // Successful login — reset counters
            failedAttempts.remove(username);
            lockoutUntil.remove(username);

            // Build safe claims. Do NOT include untrusted client-side flags like isAdmin.
            Map<String, Object> claims = new HashMap<>();
            // include canonical role from server-side user record
            claims.put("role", user.getRole());

            String token = jwt.issue(user.getUsername(), claims);

            return ResponseEntity.ok(new TokenRes(token));
        } else {
            // Failed authentication — increment attempt count and apply lockout if threshold exceeded
            failedAttempts.compute(username, (k, v) -> {
                if (v == null) return new AtomicInteger(1);
                v.incrementAndGet();
                return v;
            });

            int attempts = failedAttempts.get(username).get();
            if (attempts >= MAX_FAILED_ATTEMPTS) {
                lockoutUntil.put(username, Instant.now().plus(LOCKOUT_DURATION));
                failedAttempts.remove(username);
            }

            // Return generic error (do not reveal whether username or password was incorrect)
            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid username or password");
            return ResponseEntity.status(401).body(error);
        }
    }
}
