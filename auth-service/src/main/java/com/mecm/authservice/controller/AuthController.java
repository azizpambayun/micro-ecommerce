package com.mecm.authservice.controller;

import com.mecm.authservice.dto.*;
import com.mecm.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
@Slf4j
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<JwtAuthenticationResponse>> authenticateUser(
            @Valid @RequestBody LoginRequest loginRequest) {

        log.info("Login attempt for user: {}", loginRequest.getUsernameOrEmail());

        try {
            JwtAuthenticationResponse authResponse = authService.authenticateUser(loginRequest);
            ApiResponse<JwtAuthenticationResponse> response = ApiResponse.success(
                    "Login Successful", authResponse
            );

            log.info("Login Successful for user: {}", loginRequest.getUsernameOrEmail());
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (Exception ex) {
            log.error("Login failed for user: {} - Error {}",
                    loginRequest.getUsernameOrEmail(), ex.getMessage());
            throw ex;
        }
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<JwtAuthenticationResponse>> registerUser(
            @Valid @RequestBody SignUpRequest signUpRequest) {

        log.info("Register attempt for user: {} - with Email: {}",
                signUpRequest.getUsername(), signUpRequest.getEmail());

        try {
            JwtAuthenticationResponse authResponse = authService.registerUser(signUpRequest);
            ApiResponse<JwtAuthenticationResponse> response = ApiResponse.success(
                    "Register User Successful", authResponse
            );

            log.info("Registration successful for user: {}", signUpRequest.getUsername());
            return new ResponseEntity<>(response, HttpStatus.CREATED);

        } catch (Exception ex) {
            log.error("Registration failed for user: {} - Error {}",
                    signUpRequest.getUsername(), ex.getMessage());
            throw ex;
        }
    }

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserInfo>> getCurrentUser() {
        log.debug("Request from current user");
        try {
            UserInfo userInfo = authService.getCurrentUser();
            ApiResponse<UserInfo> response = ApiResponse.success(
                    "User Info retrieved Successfully", userInfo
            );
            log.debug("Current user info retrieved for: {}", userInfo.getUsername());
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception ex) {
            log.error("Error retrieving current user info - {}", ex.getMessage());
            throw ex;
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<JwtAuthenticationResponse>> refreshToken(
            @RequestHeader("Authorization") String bearerToken) {
        log.debug("Refresh token request");

        try {
            String token = extractTokenfromBearerString(bearerToken);

            JwtAuthenticationResponse authResponse = authService.refreshToken(token);
            ApiResponse<JwtAuthenticationResponse> response = ApiResponse.success(
                    "Token Refreshed Successfully", authResponse
            );
            log.debug("Token refreshed Successfully");
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception ex) {
            log.error("Error refreshing token - {}", ex.getMessage());
            throw ex;
        }
    }

    @PostMapping("/logout")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> logoutUser(
            @RequestHeader(value = "Authorization", required = false) String bearerToken) {

        log.debug("Logout request");

        try {
            String token = null;
            if (bearerToken != null && !bearerToken.isEmpty()) {
                token = extractTokenfromBearerString(bearerToken);
            }

            String message = authService.logoutUser(token);
            ApiResponse<String> response = ApiResponse.success(message);
            log.debug("Logout successful");
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception ex) {
            log.error("Logout Failed: {}", ex.getMessage());
            throw ex;
        }
    }

    @PostMapping("/validate-token")
    public ResponseEntity<ApiResponse<Map<String, Object>>> validateToken(
            @RequestBody TokenValidationRequest request) {
        log.debug("Token validation request");

        try {
            AuthService.TokenValidationResult validationResult = 
                    authService.validateTokenWithReason(request.getToken());

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("valid", validationResult.isValid());
            responseData.put("reason", validationResult.getReason());

            ApiResponse<Map<String, Object>> response = ApiResponse.success(
                    validationResult.getReason(),
                    responseData
            );

            log.debug("Token validation result: {} - Reason: {}", 
                    validationResult.isValid(), validationResult.getReason());

            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (Exception ex) {
            log.error("Token validation failed: {}", ex.getMessage());

            Map<String, Object> errorData = new HashMap<>();
            errorData.put("valid", false);
            errorData.put("reason", "Token validation error");

            ApiResponse<Map<String, Object>> failedResponse = ApiResponse.success(
                    "Token validation failed", errorData
            );
            return new ResponseEntity<>(failedResponse, HttpStatus.OK);
        }
    }

    @PostMapping("/forgot-password")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request) {
        log.debug("Change Password");

        try {
            String message = authService.changePassword(
                    request.getOldPassword(),
                    request.getNewPassword()
            );
            ApiResponse<String> response = ApiResponse.success(message);
            log.debug("Password changed successfully");
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception ex) {
            log.error("Password change failed: {}", ex.getMessage());
            throw ex;
        }
    }

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> health() {
        log.debug("Health check request");
        ApiResponse<String> response = ApiResponse.success(
                "Auth Service is up and running", "OK");
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/check-token-status")
    public ResponseEntity<ApiResponse<Map<String, Object>>> checkTokenStatus(
            @RequestBody TokenValidationRequest request) {
        log.debug("Token status check request");

        try {
            String token = request.getToken();
            Map<String, Object> statusData = new HashMap<>();

            // Check if token is null or empty
            if (token == null || token.isEmpty()) {
                statusData.put("exists", false);
                statusData.put("valid", false);
                statusData.put("revoked", false);
                statusData.put("message", "Token is null or empty");
            } else {
                statusData.put("exists", true);

                // Check if token is revoked
                boolean isRevoked = authService.validateToken(token); // This checks revocation internally
                AuthService.TokenValidationResult validationResult = 
                        authService.validateTokenWithReason(token);

                statusData.put("valid", validationResult.isValid());
                statusData.put("revoked", validationResult.getReason().contains("revoked"));
                statusData.put("message", validationResult.getReason());

                // Add additional token info if valid
                if (validationResult.isValid()) {
                    try {
                        long remainingTime = authService.validateToken(token) ? 1 : 0; // Simplified
                        statusData.put("hasRemainingTime", remainingTime > 0);
                    } catch (Exception e) {
                        log.warn("Could not get remaining time: {}", e.getMessage());
                    }
                }
            }

            ApiResponse<Map<String, Object>> response = ApiResponse.success(
                    "Token status retrieved successfully", 
                    statusData
            );

            log.debug("Token status check completed");
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (Exception ex) {
            log.error("Token status check failed: {}", ex.getMessage());

            Map<String, Object> errorData = new HashMap<>();
            errorData.put("exists", false);
            errorData.put("valid", false);
            errorData.put("revoked", false);
            errorData.put("message", "Error checking token status");

            ApiResponse<Map<String, Object>> failedResponse = ApiResponse.success(
                    "Token status check failed", errorData
            );
            return new ResponseEntity<>(failedResponse, HttpStatus.OK);
        }
    }

    private String extractTokenfromBearerString(String bearerToken) {
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        throw new IllegalArgumentException("Invalid token format");
    }


}
