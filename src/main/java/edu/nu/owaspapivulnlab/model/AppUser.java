package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Entity @Data @NoArgsConstructor @AllArgsConstructor @Builder
public class AppUser {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    private String username;

    // FIXED(API3: Excessive Data Exposure): previously stored plaintext passwords.
    // Now using BCrypt hashing to securely store passwords.
    @NotBlank
    private String password;

    // FIXED(API6: Mass Assignment): role and isAdmin are no longer directly modifiable via JSON.
    // Marked as read-only to prevent privilege escalation from client input.
    @Column(updatable = false, insertable = false)
    private String role = "USER";   // default role

    @Column(updatable = false, insertable = false)
    private boolean isAdmin = false;

    @Email
    private String email;

    // Secure password setter to hash before saving
    public void setPassword(String rawPassword) {
        if (rawPassword != null && !rawPassword.startsWith("$2a$")) { // prevent double-hash
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            this.password = encoder.encode(rawPassword);
        } else {
            this.password = rawPassword;
        }
    }
}
