package com.rbac.auth.controller;

import java.io.IOException;

import com.rbac.auth.dto.OtpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.rbac.auth.dto.AuthenticationRequest;
import com.rbac.auth.dto.AuthenticationResponse;
import com.rbac.auth.dto.RegisterRequest;
import com.rbac.auth.service.AuthenticationService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        logger.info("Register endpoint called for email: {}", request.getEmail());
        var response = service.register(request);
        logger.info("User registered successfully with email: {}", request.getEmail());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        logger.info("Authentication endpoint called for email: {}", request.getEmail());
        var response = service.authenticate(request);
        logger.info("User authenticated successfully for email: {}", request.getEmail());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        logger.info("Refresh token endpoint called");
        service.refreshToken(request, response);
        logger.info("Refresh token processed successfully");
    }

    @PostMapping("/send-otp")
    public ResponseEntity<String> sendOtp(@RequestBody OtpRequest request) {
        logger.info("Send OTP endpoint called for email: {}, mobile: {}", request.getEmail(), request.getMobile());
        String result = service.generateOtp(request.getEmail(), request.getMobile());
        logger.info("OTP sent successfully for email: {}, mobile: {}", request.getEmail(), request.getMobile());
        return ResponseEntity.ok(result);
    }

    @PostMapping("/login-with-otp")
    public ResponseEntity<AuthenticationResponse> loginWithOtp(@RequestBody OtpRequest request) {
        logger.info("Login with OTP endpoint called for email: {}, mobile: {}", request.getEmail(), request.getMobile());
        var response = service.loginWithOtp(request.getEmail(), request.getMobile(), request.getOtp());
        logger.info("User logged in successfully with OTP for email: {}", request.getEmail());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/loggedin-user")
    public ResponseEntity<String> getLoggedInUser() {
        logger.info("Get logged-in user endpoint called");
        String loggedInUser = service.getLoggedInUser();
        logger.info("Logged-in user retrieved: {}", loggedInUser);
        return ResponseEntity.ok(loggedInUser);
    }
}
