package edu.nu.owaspapivulnlab.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import edu.nu.owaspapivulnlab.model.AppUser;

import java.util.List;
import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);

    // FIXED(API9: Improper Inventory/SQL Injection) - replaced string concatenation with parameterized query
    @Query("SELECT u FROM AppUser u WHERE u.username LIKE %:q% OR u.email LIKE %:q%")
    List<AppUser> search(@Param("q") String q);
}
