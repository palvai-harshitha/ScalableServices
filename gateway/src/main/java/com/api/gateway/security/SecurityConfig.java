package com.api.gateway.security;

import com.api.gateway.filter.AuthenticationFilter;
import com.api.gateway.repository.UserRepository;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder; 
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationFilter authenticationFilter;

    public SecurityConfig(AuthenticationFilter authenticationFilter) {
        this.authenticationFilter = authenticationFilter;
    }
    
    
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
            .requestMatchers("/auth/authenticate").permitAll()  // Allow authentication without token
            .anyRequest().authenticated()  // Secure all other endpoints
            .and()
            .addFilterBefore(authenticationFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        return http.build();
        
    }
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        // Create an AuthenticationManager that will be used to authenticate users
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
        return authenticationManagerBuilder.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // Use hardcoded users for authentication
        return username -> {
            // Hardcoded user data
            if ("user1".equals(username)) {
                return User.builder()
                        .username("user1")
                        .password(passwordEncoder().encode("password1"))  // The password should be encoded
                        .roles("USER")
                        .build();
            } else if ("admin".equals(username)) {
                return User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("adminpass"))  // The password should be encoded
                        .roles("ADMIN")
                        .build();
            } else {
                throw new RuntimeException("User not found");
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // Use BCrypt for encoding passwords
    }
	}
    

    
    

