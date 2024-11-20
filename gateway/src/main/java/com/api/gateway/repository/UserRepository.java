package com.api.gateway.repository;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;

@Repository
public class UserRepository implements UserDetailsService {

    private static final Map<String, String> users = new HashMap<>();

    static {
        users.put("user1", "password1");
        users.put("user2", "password2");
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        if (!users.containsKey(username)) {
            throw new RuntimeException("User not found");
        }
        return User.withUsername(username)
                .password(users.get(username))
                .authorities("USER")
                .build();
    }
}
