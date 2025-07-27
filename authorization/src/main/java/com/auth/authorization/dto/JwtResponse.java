package com.auth.authorization.dto;

public record JwtResponse (
        String accessToken,
        String refreshToken,
        long expiresIn,
        long refreshExpiresIn
) {};
