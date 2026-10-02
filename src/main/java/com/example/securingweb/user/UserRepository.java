package com.example.securingweb.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    /**
     * Spring Data derives the query from the method name.
     * Optional, because "no such user" is a normal outcome, not an error.
     */
    Optional<UserEntity> findByUsername(String username);
}
