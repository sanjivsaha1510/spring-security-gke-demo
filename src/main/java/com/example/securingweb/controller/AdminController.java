package com.example.securingweb.controller;

import java.security.Principal;
import java.time.Instant;
import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    // No security annotations here: in Stage 2 the URL rule
    // requestMatchers("/admin/**").hasRole("ADMIN") protects it.
    // Principal is the plain servlet API view of the logged-in user.
    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> dashboard(Principal principal) {
        return Map.of(
                "message", "Welcome to the admin dashboard",
                "admin", principal.getName(),
                "serverTime", Instant.now().toString());
    }
}
