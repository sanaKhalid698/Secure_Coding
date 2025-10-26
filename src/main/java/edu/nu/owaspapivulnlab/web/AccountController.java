package edu.nu.owaspapivulnlab.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // FIXED: VULNERABILITY (API1 - BOLA)
    // Added check to ensure the requested account belongs to the authenticated user
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        // 1. Get the authenticated user
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous")
                           .orElse(null);

        if (me == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated.");
        }

        // 2. Retrieve the account
        Account a = accounts.findById(id)
                            .orElseThrow(() -> new RuntimeException("Account not found"));

        // 3. Verify ownership (API1 Fix)
        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body("Access denied. Account does not belong to the current user.");
        }

        // 4. Return balance
        return ResponseEntity.ok(a.getBalance());
    }

    // FIXED: VULNERABILITY (API1 - BOLA)
    // Added ownership verification and input validation
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id,
                                      @RequestParam Double amount,
                                      Authentication auth) {
        // 1. Authenticate the user
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous")
                           .orElse(null);

        if (me == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body("User not authenticated.");
        }

        // 2. Retrieve the account
        Account a = accounts.findById(id)
                            .orElseThrow(() -> new RuntimeException("Account not found"));

        // 3. Verify ownership (BOLA Fix)
        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body("Access denied. You cannot transfer from another user's account.");
        }

        // 4. Validate transfer amount
        if (amount == null || amount <= 0) {
            return ResponseEntity.badRequest().body("Invalid transfer amount.");
        }

        // 5. Perform the transfer
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);

        // 6. Prepare response
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", a.getBalance());

        return ResponseEntity.ok(response);
    }

    // still leaks more than needed
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous")
                           .orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}
