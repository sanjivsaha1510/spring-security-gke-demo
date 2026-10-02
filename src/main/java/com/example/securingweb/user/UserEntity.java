package com.example.securingweb.user;

import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

/**
 * Deliberately named UserEntity, not User, to avoid a clash with
 * org.springframework.security.core.userdetails.User.
 */
@Entity
@Table(name = "app_user")   // "user" is a reserved word in many databases
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    /** Always the ENCODED password, never plain text. */
    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private boolean enabled = true;

    /**
     * Stored WITH the ROLE_ prefix: ROLE_USER, ROLE_ADMIN.
     * If you store bare "ADMIN" here, hasRole('ADMIN') silently stops matching.
     *
     * EAGER matters: loadUserByUsername runs outside a transaction, so a LAZY
     * collection would blow up with LazyInitializationException.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "app_user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<String> roles = new HashSet<>();

    protected UserEntity() {
        // required by JPA
    }

    public UserEntity(String username, String password, Set<String> roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Set<String> getRoles() {
        return roles;
    }
}
