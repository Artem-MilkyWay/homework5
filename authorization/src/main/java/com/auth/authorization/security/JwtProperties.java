package com.auth.authorization.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;


@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtProperties {
    private String secret;
    private long accessExpirationMin;
    private long refreshExpirationDays;
}
