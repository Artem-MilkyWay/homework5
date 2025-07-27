package com.auth.authorization.service;

import com.auth.authorization.repository.RevokedTokenRepository;
import com.auth.authorization.repository.UserRepository;
import com.auth.authorization.dto.JwtResponse;
import com.auth.authorization.model.RevokedToken;
import com.auth.authorization.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final RevokedTokenRepository revokedTokenRepository;

    public User register(String login, String password, String email, Set<String> roles) {
        if (userRepository.existsByLogin(login)) {
            throw new RuntimeException("Login already exists");
        }

        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email already exists");
        }

        User user = new User(
                login,
                passwordEncoder.encode(password),
                email,
                roles
        );

        return userRepository.save(user);
    }

    public JwtResponse authenticate(String login, String password) {
        User user = userRepository.findByLogin(login)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        return jwtTokenService.generateTokens(user);
    }

    public JwtResponse refreshToken(String refreshToken) {
        if (jwtTokenService.isTokenRevoked(refreshToken)) {
            throw new RuntimeException("Token has been revoked");
        }

        String username = jwtTokenService.extractUsername(refreshToken);
        User user = userRepository.findByLogin(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return jwtTokenService.generateTokens(user);
    }

    public void revokeToken(String token) {
        String jti = jwtTokenService.extractJti(token);
        revokedTokenRepository.save(new RevokedToken(jti));
    }
}
