package com.api.gateway.controller;

import com.api.gateway.service.JwtTokenUtil;

import java.util.ArrayList;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;

    public AuthenticationController(AuthenticationManager authenticationManager, JwtTokenUtil jwtTokenUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @PostMapping("/authenticate")
    public String authenticate(@RequestParam String username, @RequestParam String password) {
        // Use the AuthenticationManager to authenticate the user
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);
        
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        // If authentication is successful, set the authentication object in the security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate and return the JWT token
        String token = jwtTokenUtil.generateToken(username);
        return "Authenticated successfully! Token: " + token;
    }
}
