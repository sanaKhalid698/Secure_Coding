package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    // VULNERABILITY(API1: BOLA/IDOR) - no ownership check, any authenticated OR anonymous GET (due to SecurityConfig) can fetch any user
    // FIXED: API1 (BOLA/IDOR) - Added ownership and role-based authorization check
    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {
        //  Ensure user is authenticated
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(401).body("Unauthorized: Please log in first.");
        }

        //  Fetch the authenticated user's record
        AppUser me = users.findByUsername(auth.getName())
                        .orElseThrow(() -> new RuntimeException("Authenticated user not found"));

        // Retrieve the target user record
        AppUser targetUser = users.findById(id)
                                .orElseThrow(() -> new RuntimeException("User not found"));

        // Check ownership OR admin privilege
        // Only the user themself OR an admin can view user details
        if (!me.getId().equals(targetUser.getId()) && !"ADMIN".equalsIgnoreCase(me.getRole())) {
            return ResponseEntity.status(403).body("Access denied: You are not authorized to view this user.");
        }

        // Return safe user details (exclude sensitive info if needed)
     
        targetUser.setPassword(null); // prevent leaking password hash

        return ResponseEntity.ok(targetUser);
    }


    // VULNERABILITY(API6: Mass Assignment) - binds role/isAdmin from client
    @PostMapping
    public AppUser create(@Valid @RequestBody AppUser body) {
        return users.save(body);
    }

    // VULNERABILITY(API9: Improper Inventory + API8 Injection style): naive 'search' that can be abused for enumeration
    @GetMapping("/search")
    public List<AppUser> search(@RequestParam String q) {
        return users.search(q);
    }

    // VULNERABILITY(API3: Excessive Data Exposure) - returns all users including sensitive fields
    // FIXED: API3 (Excessive Data Exposure) - Limit data exposure and restrict access
    @GetMapping
    public ResponseEntity<?> list(Authentication auth) {
        // Ensure only admins can view the full user list
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(401).body("Unauthorized: Please log in first.");
        }

        AppUser me = users.findByUsername(auth.getName())
                        .orElseThrow(() -> new RuntimeException("Authenticated user not found"));

        if (!"ADMIN".equalsIgnoreCase(me.getRole())) {
            return ResponseEntity.status(403).body("Access denied: Only admins can view all users.");
        }

        // Return only non-sensitive user info (no passwords or private fields)
        List<Map<String, Object>> safeUsers = users.findAll().stream()
                .map(u -> {
                    Map<String, Object> safeUser = new HashMap<>();
                    safeUser.put("id", u.getId());
                    safeUser.put("username", u.getUsername());
                    safeUser.put("role", u.getRole());
                    // Add only necessary, non-sensitive fields
                    return safeUser;
                })
                .toList();

        // Return filtered and authorized response
        return ResponseEntity.ok(safeUsers);
    }


    // FIXED(API5: Broken Function Level Authorization): only admins or owners can delete accounts
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
        AppUser currentUser = users.findByUsername(auth.getName()).orElseThrow(() -> new RuntimeException("User not found"));
        AppUser targetUser = users.findById(id).orElseThrow(() -> new RuntimeException("Target user not found"));

        // Only allow deletion if user is admin or deleting their own account
        if (!currentUser.isAdmin() && !currentUser.getId().equals(targetUser.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }

        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }

}
