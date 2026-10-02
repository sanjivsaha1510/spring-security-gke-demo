package com.example.securingweb.user;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * The ONLY new moving part in Stage 4.
 *
 * Spring Security never knew about InMemoryUserDetailsManager specifically; it
 * only ever knew this interface. Swapping the implementation is why nothing
 * else in the app has to change.
 */
@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final UserRepository repository;

    public JpaUserDetailsService(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity entity = repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("No user: " + username));

        // .authorities() takes the strings verbatim, so they must already carry
        // the ROLE_ prefix. Contrast with .roles("ADMIN"), which adds it for you.
        return User.withUsername(entity.getUsername())
                .password(entity.getPassword())        // already encoded in the DB
                .authorities(entity.getRoles().toArray(String[]::new))
                .disabled(!entity.isEnabled())
                .build();
    }
}
