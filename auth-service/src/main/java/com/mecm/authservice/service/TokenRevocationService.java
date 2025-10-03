package com.mecm.authservice.service;

import com.mecm.authservice.model.RevokedToken;
import com.mecm.authservice.repository.RevokedTokenRepository;
import com.mecm.authservice.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenRevocationService {

    private final RevokedTokenRepository revokedTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public void revokeToken(String token, String reason) {
        if (token == null || token.isEmpty()) {
            log.warn("Attempted to revoke null or empty token");
            return;
        }

        try {
            String username = jwtTokenProvider.getUsernameFromToken(token);
            Instant expiryDate = jwtTokenProvider.getExpirationDateFromToken(token);

            RevokedToken revokedToken = RevokedToken.builder()
                    .token(token)
                    .expiryDate(expiryDate)
                    .revokedAt(Instant.now())
                    .username(username)
                    .reason(reason)
                    .build();

            revokedTokenRepository.save(revokedToken);
            log.info("Token revoked for user: {} - Reason: {}", username, reason);

        } catch (Exception ex) {
            log.error("Error revoking token: {}", ex.getMessage());
        }
    }

    @Transactional(readOnly = true)
    public boolean isTokenRevoked(String token) {
        return revokedTokenRepository.existsByToken(token);
    }

    @Scheduled(cron = "0 0 2 * * ?") // Run daily at 2 AM
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Starting cleanup of expired revoked tokens");
        revokedTokenRepository.deleteExpiredTokens(Instant.now());
        log.info("Cleanup of expired revoked tokens completed");
    }
}
