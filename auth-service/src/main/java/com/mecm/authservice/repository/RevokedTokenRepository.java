package com.mecm.authservice.repository;

import com.mecm.authservice.model.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;

@Repository
public interface RevokedTokenRepository extends JpaRepository<RevokedToken, Long> {

    boolean existsByToken(String token);

    @Modifying
    @Query("DELETE FROM RevokedToken r WHERE r.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") Instant now);
}
