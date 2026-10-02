package com.example.securingweb.controller;

import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.securingweb.jwt.TokenService;

@RestController
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    public AuthController(AuthenticationManager authenticationManager, TokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
    }

    public record LoginRequest(String username, String password) {}

    /**
     * The one place in the JWT world where a password is still involved.
     *
     * Note that this endpoint does NOT check the password itself. It builds an
     * unauthenticated token and hands it to the AuthenticationManager, which
     * runs the same DaoAuthenticationProvider -> JpaUserDetailsService ->
     * PasswordEncoder path that Basic auth uses. Identical authentication,
     * different result: a JWT instead of a session.
     *
     * Bad credentials throw AuthenticationException, which surfaces as 401.
     */
    @PostMapping("/auth/token")
    public Map<String, String> token(@RequestBody LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        return Map.of("token", tokenService.generateToken(authentication));
    }
}
