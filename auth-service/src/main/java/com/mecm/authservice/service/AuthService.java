package com.mecm.authservice.service;

import com.mecm.authservice.dto.JwtAuthenticationResponse;
import com.mecm.authservice.dto.LoginRequest;
import com.mecm.authservice.dto.SignUpRequest;
import com.mecm.authservice.dto.UserInfo;
import com.mecm.authservice.exception.BadRequestException;
import com.mecm.authservice.exception.ResourceNotFoundException;
import com.mecm.authservice.model.Role;
import com.mecm.authservice.model.User;
import com.mecm.authservice.repository.UserRepository;
import com.mecm.authservice.security.JwtTokenProvider;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final TokenRevocationService tokenRevocationService;

    public JwtAuthenticationResponse authenticateUser(LoginRequest loginRequest) {
        log.info("Attempting authentication for user: {}", loginRequest.getUsernameOrEmail());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsernameOrEmail(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String jwt = jwtTokenProvider.generateToken(authentication);

            User user = (User) authentication.getPrincipal();

            UserInfo userInfo = createUserInfo(user);

            Long expiresIn = jwtTokenProvider.getRemainingTimeInMs(jwt) / 1000;

            log.info("Authentication successful for user: {}", user.getUsername());

            return new JwtAuthenticationResponse(jwt, expiresIn, userInfo);

        } catch (AuthenticationException ex) {
            log.error("Authentication failed for user: {} - {}",
                    loginRequest.getUsernameOrEmail(), ex.getMessage());
            throw new BadCredentialsException("Invalid username or password", ex);
        }
    }

    public JwtAuthenticationResponse registerUser(SignUpRequest signUpRequest) {
        log.info("Attempting registration for user: {} with email: {}",
                signUpRequest.getUsername(), signUpRequest.getEmail());

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            log.warn("Registration failed - Username already taken: {}", signUpRequest.getUsername());
            throw new BadRequestException("Username already taken");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            log.warn("Registration failed - Email already taken: {}", signUpRequest.getEmail());
            throw new BadRequestException("Email already taken");
        }

        User user = User.builder()
                .username(signUpRequest.getUsername())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .fullName(signUpRequest.getFullName())
                .build();

        user.setRole(Role.USER);

        User savedUser = userRepository.save(user);
        log.info("Registration successful for user: {}", savedUser.getUsername());

        String jwt = jwtTokenProvider.generateTokenFromUsername(savedUser.getUsername());

        UserInfo userInfo = createUserInfo(savedUser);

        Long expiresIn = jwtTokenProvider.getRemainingTimeInMs(jwt) / 1000;

        return new JwtAuthenticationResponse(jwt, expiresIn, userInfo);
    }

    private UserInfo createUserInfo(User user) {
        return new UserInfo(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFullName(),
                user.getRole().name()
        );
    }

    @Transactional(readOnly = true)
    public UserInfo getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new BadRequestException("User is not authenticated");
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        User currentUser = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        log.debug("Retrieved current user: {}", currentUser.getUsername());
        return createUserInfo(currentUser);
    }

    @Transactional(readOnly = true)
    public boolean validateToken(String token) {
        try {
            if (token == null || token.isEmpty()) {
                log.warn("Token validation failed - Token is null or empty");
                return false;
            }

            // Check if token is revoked first (most important check)
            if (tokenRevocationService.isTokenRevoked(token)) {
                log.warn("Token validation failed - Token has been revoked");
                return false;
            }

            // Then validate token structure and expiration
            if (!jwtTokenProvider.validateToken(token)) {
                log.warn("Token validation failed - Token is invalid or expired");
                return false;
            }

            // Finally check if user still exists
            String username = jwtTokenProvider.getUsernameFromToken(token);
            boolean userExists = userRepository.findByUsername(username).isPresent();

            if (!userExists) {
                log.warn("Token validation failed - User {} not found", username);
            } else {
                log.debug("Token validation successful for user: {}", username);
            }

            return userExists;

        } catch (Exception ex) {
            log.error("Token validation error: {}", ex.getMessage());
            return false;
        }
    }

    public JwtAuthenticationResponse refreshToken(String token) {
        // Check if token is already revoked
        if (tokenRevocationService.isTokenRevoked(token)) {
            throw new BadRequestException("Token has already been used or revoked");
        }

        if (!jwtTokenProvider.validateToken(token)) {
            throw new BadRequestException("Token is invalid or expired");
        }

        String username = jwtTokenProvider.getUsernameFromToken(token);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Revoke the old token before generating a new one
        tokenRevocationService.revokeToken(token, "TOKEN_REFRESH");

        String newToken = jwtTokenProvider.generateTokenFromUsername(username);
        Long expiresIn = jwtTokenProvider.getRemainingTimeInMs(newToken) / 1000;
        UserInfo userInfo = createUserInfo(user);

        log.info("Token refreshed for user: {} - Old token revoked", username);

        return new JwtAuthenticationResponse(newToken, expiresIn, userInfo);
    }

    public String logoutUser(String token) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            User user = (User) authentication.getPrincipal();

            // Revoke the token on logout
            if (token != null && !token.isEmpty()) {
                tokenRevocationService.revokeToken(token, "LOGOUT");
            }

            log.info("User logged out: {}", user.getUsername());

            SecurityContextHolder.clearContext();

            return "Logout successful";
        }
        return "User is not in session";
    }

    public String changePassword(String oldPassword, String newPassword) {
        User currentUser = getCurrentUserEntity();

        if (!passwordEncoder.matches(oldPassword, currentUser.getPassword())) {
            throw new BadRequestException("Old password is incorrect");
        }

        if (passwordEncoder.matches(newPassword, currentUser.getPassword())) {
            throw new BadRequestException("New password cannot be the same as the old password");
        }

        currentUser.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(currentUser);

        log.info("Password changed for user: {}", currentUser.getUsername());

        return "Password changed successfully";

    }

    private User getCurrentUserEntity() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new BadRequestException("User is not authenticated");
        }

        User user = (User) authentication.getPrincipal();

        return userRepository.findById(user.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    @Transactional(readOnly = true)
    public TokenValidationResult validateTokenWithReason(String token) {
        try {
            if (token == null || token.isEmpty()) {
                return new TokenValidationResult(false, "Token is null or empty");
            }

            // Check if token is revoked
            if (tokenRevocationService.isTokenRevoked(token)) {
                return new TokenValidationResult(false, "Token has been revoked");
            }

            // Validate token structure and expiration
            if (!jwtTokenProvider.validateToken(token)) {
                return new TokenValidationResult(false, "Token is invalid or expired");
            }

            // Check if user exists
            String username = jwtTokenProvider.getUsernameFromToken(token);
            boolean userExists = userRepository.findByUsername(username).isPresent();

            if (!userExists) {
                return new TokenValidationResult(false, "User not found");
            }

            return new TokenValidationResult(true, "Token is valid");

        } catch (Exception ex) {
            log.error("Token validation error: {}", ex.getMessage());
            return new TokenValidationResult(false, "Token validation error: " + ex.getMessage());
        }
    }

    // Inner class for detailed validation result
    @Getter
    public static class TokenValidationResult {
        private final boolean valid;
        private final String reason;

        public TokenValidationResult(boolean valid, String reason) {
            this.valid = valid;
            this.reason = reason;
        }

    }

}
