package com.auth.authorization.controller;

import com.auth.authorization.service.AuthService;
import com.auth.authorization.dto.JwtResponse;
import com.auth.authorization.dto.LoginRequest;
import com.auth.authorization.dto.RefreshTokenRequest;
import com.auth.authorization.dto.RegistrationRequest;
import com.auth.authorization.model.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegistrationRequest request) {
        User user = authService.register(
                request.getLogin(),
                request.getPassword(),
                request.getEmail(),
                Set.of("guest")
        );
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody @Valid LoginRequest request) {
        JwtResponse response = authService.authenticate(request.getLogin(), request.getPassword());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refresh(@RequestBody @Valid RefreshTokenRequest request) {
        JwtResponse response = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody @Valid RefreshTokenRequest request) {
        authService.revokeToken(request.getRefreshToken());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/check-auth")
    public String checkAuth() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Current user: " + auth.getName() + ", roles: " + auth.getAuthorities();
    }
}
