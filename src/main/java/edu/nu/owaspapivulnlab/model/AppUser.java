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

    // VULNERABILITY(API6: Mass Assignment): role and isAdmin are bindable via incoming JSON
    private String role;   // e.g., "USER" or "ADMIN"
    private boolean isAdmin;

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
