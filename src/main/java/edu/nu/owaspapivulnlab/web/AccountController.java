package edu.nu.owaspapivulnlab.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Refill;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    // Map to store user-specific buckets for rate limiting
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // Helper method to create/get a bucket per user
    private Bucket resolveBucket(String username) {
        return buckets.computeIfAbsent(username, k -> {
            // API4: Rate Limiting – allow 5 requests per minute per user
            Bandwidth limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
            return Bucket.builder().addLimit(limit).build();
        });
    }

    // ----------------------------
    // GET /{id}/balance
    // API1: BOLA fix – ownership check
    // API4: Rate Limiting
    // ----------------------------
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated.");
        }

        Bucket bucket = resolveBucket(auth.getName());
        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                                 .body("Too many requests. Please try again later.");
        }

        // Authenticate user
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        if (me == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated.");
        }

        // Retrieve account
        Account a = accounts.findById(id)
                            .orElseThrow(() -> new RuntimeException("Account not found"));

        // API1: BOLA – verify ownership
        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body("Access denied. Account does not belong to the current user.");
        }

        return ResponseEntity.ok(a.getBalance());
    }

    // ----------------------------
    // POST /{id}/transfer
    // API1: BOLA fix – ownership check
    // API2: Input Validation – amount > 0
    // API4: Rate Limiting
    // ----------------------------
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id,
                                      @RequestParam Double amount,
                                      Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated.");
        }

        Bucket bucket = resolveBucket(auth.getName());
        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                                 .body("Too many requests. Please try again later.");
        }

        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        if (me == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated.");
        }

        Account a = accounts.findById(id)
                            .orElseThrow(() -> new RuntimeException("Account not found"));

        // API1: BOLA – verify ownership
        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body("Access denied. You cannot transfer from another user's account.");
        }

        // API2: Validate transfer amount
        if (amount == null || amount <= 0) {
            return ResponseEntity.badRequest().body("Invalid transfer amount.");
        }

        a.setBalance(a.getBalance() - amount);
        accounts.save(a);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", a.getBalance());
        return ResponseEntity.ok(response);
    }

    // ----------------------------
    // GET /mine
    // API3: Safe Data Exposure – only non-sensitive fields
    // API4: Rate Limiting
    // ----------------------------
    @GetMapping("/mine")
    public ResponseEntity<?> mine(Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated.");
        }

        Bucket bucket = resolveBucket(auth.getName());
        if (!bucket.tryConsume(1)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                                 .body("Too many requests. Please try again later.");
        }

        AppUser me = users.findByUsername(auth.getName())
                           .orElseThrow(() -> new RuntimeException("Authenticated user not found"));

        // API3: Return only safe account details
        var safeAccounts = accounts.findByOwnerUserId(me.getId()).stream()
                .map(a -> {
                    Map<String, Object> map = new HashMap<>();
                    map.put("id", a.getId());
                    map.put("balance", a.getBalance());
                    map.put("name", a.getName()); // Non-sensitive field only
                    return map;
                })
                .toList();

        return ResponseEntity.ok(safeAccounts);
    }

}
