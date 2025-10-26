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
        // Optional: mask password or private fields
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
    @GetMapping
    public List<AppUser> list() {
        return users.findAll();
    }

    // VULNERABILITY(API5: Broken Function Level Authorization) - allows regular users to delete anyone
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}
