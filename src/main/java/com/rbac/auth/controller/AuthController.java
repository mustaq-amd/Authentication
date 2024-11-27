package com.rbac.auth.controller;

import java.io.IOException;

import com.rbac.auth.dto.OtpRequest;
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

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        service.refreshToken(request, response);
    }

    @PostMapping("/send-otp")
    public ResponseEntity<String> sendOtp(@RequestBody OtpRequest request) {
        return ResponseEntity.ok(service.generateOtp(request.getEmail(), request.getMobile()));
    }

    @PostMapping("/login-with-otp")
    public ResponseEntity<AuthenticationResponse> loginWithOtp(@RequestBody OtpRequest request) {
        return ResponseEntity.ok(service.loginWithOtp(request.getEmail(), request.getMobile(), request.getOtp()));
    }

    @GetMapping("/loggedin-user")
    public ResponseEntity<String> getLoggedInUser() {
        return ResponseEntity.ok(service.getLoggedInUser());
    }




}

