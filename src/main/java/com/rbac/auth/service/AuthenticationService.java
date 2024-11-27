package com.rbac.auth.service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Random;

import com.rbac.auth.entity.Otp;
import com.rbac.auth.repository.OtpRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rbac.auth.dto.AuthenticationRequest;
import com.rbac.auth.dto.AuthenticationResponse;
import com.rbac.auth.dto.RegisterRequest;
import com.rbac.auth.entity.Token;
import com.rbac.auth.entity.User;
import com.rbac.auth.enums.TokenType;
import com.rbac.auth.repository.TokenRepository;
import com.rbac.auth.repository.UserRepository;
import com.rbac.auth.security.config.JwtService;
import com.rbac.exception.UserAlreadyExistException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final NotificationService notificationService;
    private final OtpRepository otpRepository;

    public AuthenticationResponse register(RegisterRequest request) {
        logger.info("Attempting to register user with email: {}", request.getEmail());
        if (isUserAlreadyExist(request.getEmail())) {
            logger.error("User already exists with email: {}", request.getEmail());
            throw new UserAlreadyExistException("User already exist with email : " + request.getEmail());
        }

        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        var savedUser = repository.save(user);
        logger.info("User successfully registered with email: {}", request.getEmail());

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);

        logger.debug("Tokens generated for user: {}", request.getEmail());
        return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken).build();
    }

    private boolean isUserAlreadyExist(String email) {
        logger.debug("Checking if user already exists with email: {}", email);
        return repository.findByEmail(email).isPresent();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        logger.info("Authenticating user with email: {}", request.getEmail());
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        logger.info("Authentication successful for user: {}", request.getEmail());

        var user = repository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);

        logger.debug("Tokens generated for authenticated user: {}", request.getEmail());
        return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken).build();
    }

    private void saveUserToken(User user, String jwtToken) {
        logger.debug("Saving token for user: {}", user.getEmail());
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .createdAt(LocalDateTime.now())
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        logger.debug("Revoking all tokens for user: {}", user.getEmail());
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty()) {
            logger.info("No valid tokens found for user: {}", user.getEmail());
            return;
        }
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        logger.info("Refreshing token...");
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.error("Authorization header is missing or invalid");
            return;
        }
        final String refreshToken = authHeader.substring(7);
        final String userEmail = jwtService.extractUsername(refreshToken);

        if (userEmail != null) {
            logger.debug("Extracted user email: {}", userEmail);
            var user = this.repository.findByEmail(userEmail).orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                logger.info("Refresh token is valid for user: {}", userEmail);
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);

                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            } else {
                logger.warn("Invalid refresh token for user: {}", userEmail);
            }
        }
    }

    public AuthenticationResponse loginWithOtp(String email, String mobile, String otp) {
        logger.info("Attempting OTP login for email: {} or mobile: {}", email, mobile);
        Otp otpRecord;
        if (email != null && !email.isEmpty()) {
            otpRecord = otpRepository.findByEmailAndOtpAndUsedFalse(email, otp)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid or expired OTP"));
        } else if (mobile != null && !mobile.isEmpty()) {
            otpRecord = otpRepository.findByMobileAndOtpAndUsedFalse(mobile, otp)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid or expired OTP"));
        } else {
            throw new IllegalArgumentException("Either email or mobile must be provided");
        }

        if (otpRecord.getExpiresAt().isBefore(LocalDateTime.now())) {
            logger.error("OTP expired for email: {} or mobile: {}", email, mobile);
            throw new IllegalArgumentException("OTP has expired!");
        }

        logger.info("OTP validated successfully for email: {} or mobile: {}", email, mobile);
        otpRecord.setUsed(true);
        otpRepository.save(otpRecord);

        var user = email != null ? repository.findByEmail(email).orElseThrow() :
                repository.findByMobile(mobile).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);

        logger.info("Login with OTP successful for user: {}", email != null ? email : mobile);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public String generateOtp(String email, String mobile) {
        logger.info("Generating OTP for email: {} or mobile: {}", email, mobile);
        if ((email == null || email.isEmpty()) && (mobile == null || mobile.isEmpty())) {
            logger.error("Both email and mobile are missing");
            throw new IllegalArgumentException("Either email or mobile must be provided");
        }

        String otp = String.format("%06d", new Random().nextInt(999999)); // Generate a 6-digit OTP
        var otpRecord = Otp.builder()
                .email(email)
                .mobile(mobile)
                .otp(otp)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(5)) // Valid for 5 minutes
                .build();
        otpRepository.save(otpRecord);

        if (email != null && !email.isEmpty()) {
            logger.debug("Sending OTP via email to: {}", email);
            notificationService.sendEmailOtp(email, otp);
//        } else if (mobile != null && !mobile.isEmpty()) {
//            notificationService.sendSmsOtp(mobile, otp);
//        }
        }

        return "OTP sent successfully!";
    }

    public String getLoggedInUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Currently logged-in user: {}", username);
        return username;
    }
}
