package com.example.securingweb.jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private final JwtEncoder encoder;

    public TokenService(JwtEncoder encoder) {
        this.encoder = encoder;
    }

    /**
     * Turns a successful authentication into a signed token.
     *
     * Everything the server will later need is packed INTO the token, because
     * after this method returns the server keeps no record of the session at
     * all. That is what "stateless" means in practice.
     */
    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();

        // Space-separated, e.g. "ROLE_USER ROLE_ADMIN".
        // JwtGrantedAuthoritiesConverter splits on whitespace by default.
        String roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("spring-security-demo")
                .issuedAt(now)
                .expiresAt(now.plus(30, ChronoUnit.MINUTES))   // short-lived on purpose
                .subject(authentication.getName())             // becomes authentication.name
                .claim("roles", roles)
                .build();

        return encoder.encode(
                JwtEncoderParameters.from(JwsHeader.with(() -> "RS256").build(), claims))
                .getTokenValue();
    }
}
