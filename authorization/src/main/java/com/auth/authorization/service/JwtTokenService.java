package com.auth.authorization.service;

import com.auth.authorization.security.JwtProperties;
import com.auth.authorization.dto.JwtResponse;
import com.auth.authorization.model.User;
import com.auth.authorization.repository.RevokedTokenRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtTokenService {

    private final RevokedTokenRepository revokedTokenRepository;
    private final JwtProperties jwtProperties;

    private static final JWEAlgorithm JWE_ALG = JWEAlgorithm.DIR;
    private static final EncryptionMethod JWE_ENC = EncryptionMethod.A256GCM;

    private byte[] getEncryptionKey() {
        return Base64.getDecoder().decode(jwtProperties.getSecret());
    }

    private String createJweToken(Map<String, Object> claims, Instant expiration) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject((String) claims.get("sub"))
                .claim("userId", claims.get("userId"))
                .claim("email", claims.get("email"))
                .claim("roles", claims.get("roles"))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(expiration))
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWEHeader header = new JWEHeader(JWE_ALG, JWE_ENC);
        Payload payload = new Payload(claimsSet.toJSONObject());
        JWEObject jwe = new JWEObject(header, payload);
        jwe.encrypt(new DirectEncrypter(getEncryptionKey()));
        return jwe.serialize();
    }

    public JwtResponse generateTokens(User user) {
        try {
            Instant now = Instant.now();
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", user.getLogin());
            claims.put("userId", user.getId().toString());
            claims.put("email", user.getEmail());
            claims.put("roles", user.getRoles());

            String accessToken = createJweToken(
                    claims,
                    now.plus(jwtProperties.getAccessExpirationMin(), ChronoUnit.MINUTES)
            );

            String refreshToken = createJweToken(
                    claims,
                    now.plus(jwtProperties.getRefreshExpirationDays(), ChronoUnit.DAYS)
            );

            return new JwtResponse(
                    accessToken,
                    refreshToken,
                    jwtProperties.getAccessExpirationMin() * 60,
                    jwtProperties.getRefreshExpirationDays() * 24 * 60 * 60
            );
        } catch (JOSEException e) {
            log.error(e.getMessage());
            throw new RuntimeException("JWE token creation failed", e);
        }
    }

    private JWTClaimsSet decryptJweToken(String token) throws ParseException, JOSEException {
        try {
            JWEObject jwe = JWEObject.parse(token);
            jwe.decrypt(new DirectDecrypter(getEncryptionKey()));;
            return JWTClaimsSet.parse(jwe.getPayload().toJSONObject());
        } catch (Exception e) {
            log.error("Full JWE decryption error", e);
            throw e;
        }
    }

    public boolean validateToken(String token) {
        try {
            decryptJweToken(token);
            return true;
        } catch (ParseException | JOSEException e) {
            log.error("Invalid JWE token: {}", e.getMessage());
            return false;
        }
    }

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public UUID extractUserId(String token) {
        String userId = extractClaim(token, claims -> {
            try {
                return claims.getStringClaim("userId");
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        });
        return userId != null ? UUID.fromString(userId) : null;
    }

    public Set<String> extractRoles(String token) {
        try {
            List<String> roles = decryptJweToken(token).getStringListClaim("roles");
            return roles != null ? new HashSet<>(roles) : Collections.emptySet();
        } catch (Exception e) {
            return Collections.emptySet();
        }
    }

    public String extractJti(String token) {
        return extractClaim(token, JWTClaimsSet::getJWTID);
    }

    public String extractEmail(String token) {
        return extractClaim(token, claims -> {
            try {
                return claims.getStringClaim("email");
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, JWTClaimsSet::getExpirationTime);
    }

    private <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        try {
            JWTClaimsSet claims = decryptJweToken(token);
            return claimsResolver.apply(claims);
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract claim from JWE", e);
        }
    }

    public boolean isTokenRevoked(String token) {
        try {
            String jti = extractJti(token);
            Date expiration = extractExpiration(token);
            return expiration.before(new Date()) || revokedTokenRepository.existsByJti(jti);
        } catch (Exception e) {
            return true;
        }
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                extractUsername(token),
                "",
                extractRoles(token).stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList())
        );
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}