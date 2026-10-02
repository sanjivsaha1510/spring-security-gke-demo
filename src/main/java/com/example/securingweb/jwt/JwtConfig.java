package com.example.securingweb.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Everything JWT-specific lives here so SecurityConfig stays readable.
 *
 * Asymmetric (RSA) signing: the private key SIGNS tokens, the public key
 * VERIFIES them. That split is the whole point — an auth server can hand out
 * its public key so any number of services can verify tokens without ever
 * being able to mint one.
 */
@Configuration
public class JwtConfig {

    /**
     * Generated fresh on every startup, which means every restart invalidates
     * all outstanding tokens. Fine for a demo, and a useful thing to notice.
     * A real system loads a stable key from a keystore, a secret manager, or
     * fetches the public key from the issuer's JWKS endpoint.
     */
    @Bean
    KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /** Signs tokens. Needs the PRIVATE key. */
    @Bean
    JwtEncoder jwtEncoder(KeyPair keyPair) {
        RSAKey jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Verifies tokens. Needs only the PUBLIC key.
     * Also checks expiry and signature automatically — this is the work you
     * would otherwise hand-write (badly) in a custom OncePerRequestFilter.
     */
    @Bean
    JwtDecoder jwtDecoder(KeyPair keyPair) {
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
    }

    /**
     * THE STAGE 5 GOTCHA.
     *
     * By default Spring reads the "scope" claim and prefixes each value with
     * "SCOPE_", so you would get SCOPE_ROLE_ADMIN and hasRole('ADMIN') would
     * stop matching — the ROLE_ prefix problem again, wearing a new hat.
     *
     * Here we read our own "roles" claim and add no prefix, because the values
     * in the token already read ROLE_USER / ROLE_ADMIN.
     */
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName("roles");
        authorities.setAuthorityPrefix("");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }
}
