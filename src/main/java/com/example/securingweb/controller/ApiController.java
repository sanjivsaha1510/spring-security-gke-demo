package com.example.securingweb.controller;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.bind.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately mirrors /user and /admin so you can call the SAME logical
 * endpoints two ways and compare:
 *
 *   /user/profile      -> session or Basic auth   (chain 2)
 *   /api/user/profile  -> Bearer token            (chain 1)
 *
 * The @PreAuthorize rules below are unchanged from Stage 3. Method security
 * does not care how you authenticated — it only reads the SecurityContext.
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    /**
     * The principal here is a Jwt, not a UserDetails. No database lookup
     * happened on this request: everything came out of the token.
     */
    @GetMapping("/user/profile")
    public Map<String, Object> profile(Authentication authentication,
                                       @AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList(),
                "principalType", authentication.getPrincipal().getClass().getSimpleName(),
                "issuedAt", String.valueOf(jwt.getIssuedAt()),
                "expiresAt", String.valueOf(jwt.getExpiresAt()),
                "claims", jwt.getClaims().keySet());
    }

    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> dashboard(Authentication authentication) {
        return Map.of(
                "message", "Admin dashboard, reached with a bearer token",
                "admin", authentication.getName());
    }

    /** Same ownership rule as Stage 3, now driven by the token's subject. */
    @GetMapping("/user/profile/{username}")
    @PreAuthorize("#username == authentication.name or hasRole('ADMIN')")
    public Map<String, Object> profileOf(@PathVariable String username) {
        return Map.of(
                "username", username,
                "email", username + "@example.com");
    }
}
