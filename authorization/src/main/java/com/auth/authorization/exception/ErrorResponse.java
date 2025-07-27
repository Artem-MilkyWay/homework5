package com.auth.authorization.exception;

import java.util.Map;

public record ErrorResponse(
        String message,
        Map<String, String> errors
) {}
