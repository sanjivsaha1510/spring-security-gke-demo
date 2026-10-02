package com.example.securingweb;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * STAGE 2 ONLY. For Stage 1, leave this file out of the project
 * (or comment out @Configuration) so Spring Boot's defaults apply.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    // ---------------------------------------------------------------
    // CHAIN 1: the stateless API
    // ---------------------------------------------------------------
    @Bean
    @Order(1)
    SecurityFilterChain apiFilterChain(HttpSecurity http,
                                       JwtAuthenticationConverter converter) throws Exception {
        http
                // Only requests matching these paths enter this chain.
                .securityMatcher("/api/**", "/auth/**")

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/token").permitAll()   // the login endpoint itself
                        .anyRequest().authenticated())

                // No session is created and none is read. Every request must carry
                // its own proof of identity.
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Safe to disable HERE, and only here. CSRF attacks work because a
                // browser attaches cookies automatically to cross-site requests. A
                // bearer token is never attached automatically — an attacker's page
                // cannot read it out of the victim's storage and set the header.
                // Chain 2 below uses cookies, so it keeps CSRF protection on.
                .csrf(csrf -> csrf.disable())

                // Installs BearerTokenAuthenticationFilter: reads the
                // Authorization: Bearer header, calls JwtDecoder (signature +
                // expiry), converts claims to authorities, populates the context.
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(converter)))

                // No login page for an API. 401 with a WWW-Authenticate header.
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable());

        return http.build();
    }

    // ---------------------------------------------------------------
    // CHAIN 2: the session-based app, unchanged from Stage 4
    // ---------------------------------------------------------------
    @Bean
    @Order(2)
    SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
                // No securityMatcher, so this chain is the catch-all.
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**", "/error").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()
                        //.requestMatchers("/admin/**").hasRole("ADMIN")   // checks authority ROLE_ADMIN
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
                .headers(h -> h.frameOptions(f -> f.sameOrigin()));

        return http.build();
    }

    // Defining this bean switches off Boot's generated "user" account.
    /*@Bean
    UserDetailsService userDetailsService(PasswordEncoder encoder) {
        var alice = User.withUsername("alice")
                .password(encoder.encode("password"))
                .roles("USER")                 // stored as ROLE_USER
                .build();

        var bob = User.withUsername("bob")
                .password(encoder.encode("password"))
                .roles("USER", "ADMIN")        // stored as ROLE_USER, ROLE_ADMIN
                .build();

        return new InMemoryUserDetailsManager(alice, bob);
    }*/

    // Stores hashes as "{bcrypt}$2a$10$...", so the algorithm can change later
    // without breaking existing passwords.
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Needed because AuthController calls it directly. Spring assembles it from
     * the beans already present: JpaUserDetailsService + PasswordEncoder, via
     * DaoAuthenticationProvider. Both chains authenticate the same users.
     */
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
