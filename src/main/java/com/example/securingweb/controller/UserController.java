package com.example.securingweb.controller;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    // Spring MVC injects the Authentication object that the security filters
    // placed in the SecurityContextHolder. Returning its contents lets you
    // see exactly what Spring Security knows about the caller.
    @GetMapping("/profile")
    public Map<String, Object> profile(Authentication authentication) {
        return Map.of(
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList(),
                "authenticationType", authentication.getClass().getSimpleName());
    }


    /**
     * A more realistic variant: the owner OR an admin may read it.
     * This single line is the pattern behind most real authorization rules.
     */
    @GetMapping("/profile/{username}/details")
    @PreAuthorize("#username == authentication.name and hasRole('USER')")
    public Map<String, Object> detailsOf(@PathVariable String username) {
        return Map.of(
                "username", username,
                "phone", "+91-90000-00000",
                "note", "Visible to the owner and to admins");
    }
}
