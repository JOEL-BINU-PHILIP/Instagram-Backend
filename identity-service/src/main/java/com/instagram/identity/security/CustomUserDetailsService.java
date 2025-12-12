package com.instagram.identity.security;

import com.instagram.identity.model.User;
import com.instagram.identity.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

/**
 * This class tells Spring Security HOW to load users from the database.
 *
 * When someone logs in:
 *   Spring Security → calls loadUserByUsername()
 *   We → fetch user from MongoDB
 *   We → return a Spring UserDetails object
 *
 * The returned UserDetails object contains:
 *   - username
 *   - hashed password
 *   - list of authorities (roles)
 *
 * If user is not found → login fails.
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository repo) {
        this.userRepository = repo;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Try to find user in DB, if not found → throw exception
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        /**
         * Convert our User object → Spring Security UserDetails object.
         *
         * Important:
         *  user.getRoles() returns a Set<Role>
         *  Spring Security expects something like:
         *     new SimpleGrantedAuthority("ROLE_ADMIN")
         */
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPasswordHash(),
                user.getRoles()
                        .stream()
                        .map(role -> new SimpleGrantedAuthority(role.getName()))
                        .collect(Collectors.toList())
        );
    }
}
