package com.example.securingweb.user;

import java.util.Set;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Demo convenience only. A real app would use Flyway or Liquibase.
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private final UserRepository repository;
    private final PasswordEncoder encoder;

    public DataSeeder(UserRepository repository, PasswordEncoder encoder) {
        this.repository = repository;
        this.encoder = encoder;
    }

    @Override
    public void run(String... args) {
        if (repository.count() > 0) {
            return;   // already seeded
        }

        // encode() exactly once. Encoding an already-encoded value is the
        // classic cause of "password looks right but login fails".
        repository.save(new UserEntity(
                "alice",
                encoder.encode("password"),
                Set.of("ROLE_USER")));

        repository.save(new UserEntity(
                "bob",
                encoder.encode("password"),
                Set.of("ROLE_USER", "ROLE_ADMIN")));

        System.out.println(">>> Seeded users: " + repository.count());
        repository.findAll().forEach(u ->
                System.out.println(">>>   " + u.getUsername() + " " + u.getRoles()
                        + " " + u.getPassword()));
    }
}
