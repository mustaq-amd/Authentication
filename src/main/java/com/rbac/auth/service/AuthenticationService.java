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

@Service
@RequiredArgsConstructor
public class AuthenticationService {

	private final UserRepository repository;
	private final TokenRepository tokenRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	private final NotificationService notificationService;
	private final OtpRepository otpRepository;

	public AuthenticationResponse register(RegisterRequest request) {
		if(isUserAlreadyExist(request.getEmail())) {
			throw new UserAlreadyExistException("User already exist with email : "+request.getEmail());
		}
		var user = User.builder().firstname(request.getFirstname()).lastname(request.getLastname())
				.email(request.getEmail()).password(passwordEncoder.encode(request.getPassword()))
				.role(request.getRole()).build();
		var savedUser = repository.save(user);
		var jwtToken = jwtService.generateToken(user);
		var refreshToken = jwtService.generateRefreshToken(user);
		saveUserToken(savedUser, jwtToken);
		return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken).build();
	}

	private boolean isUserAlreadyExist(String email) {
		return repository.findByEmail(email).isPresent();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
		var user = repository.findByEmail(request.getEmail()).orElseThrow();
		var jwtToken = jwtService.generateToken(user);
		var refreshToken = jwtService.generateRefreshToken(user);
		revokeAllUserTokens(user);
		saveUserToken(user, jwtToken);
		return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken).build();
	}

	private void saveUserToken(User user, String jwtToken) {
		var token = Token.builder().user(user).token(jwtToken).tokenType(TokenType.BEARER).expired(false).revoked(false)
				.build();
		tokenRepository.save(token);
	}

	private void revokeAllUserTokens(User user) {
		var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
		if (validUserTokens.isEmpty())
			return;
		validUserTokens.forEach(token -> {
			token.setExpired(true);
			token.setRevoked(true);
		});
		tokenRepository.saveAll(validUserTokens);
	}

	public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
		final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		final String refreshToken;
		final String userEmail;
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			return;
		}
		refreshToken = authHeader.substring(7);
		userEmail = jwtService.extractUsername(refreshToken);
		if (userEmail != null) {
			var user = this.repository.findByEmail(userEmail).orElseThrow();
			if (jwtService.isTokenValid(refreshToken, user)) {
				var accessToken = jwtService.generateToken(user);
				revokeAllUserTokens(user);
				saveUserToken(user, accessToken);
				var authResponse = AuthenticationResponse.builder().accessToken(accessToken).refreshToken(refreshToken)
						.build();
				new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
			}
		}
	}

	public AuthenticationResponse loginWithOtp(String email, String mobile, String otp) {
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
			throw new IllegalArgumentException("OTP has expired!");
		}

		// Mark OTP as used
		otpRecord.setUsed(true);
		otpRepository.save(otpRecord);

		// Load user and generate tokens
		var user = email != null ? repository.findByEmail(email).orElseThrow() :
				repository.findByMobile(mobile).orElseThrow();
		var jwtToken = jwtService.generateToken(user);
		var refreshToken = jwtService.generateRefreshToken(user);
		revokeAllUserTokens(user);
		saveUserToken(user, jwtToken);

		return AuthenticationResponse.builder()
				.accessToken(jwtToken)
				.refreshToken(refreshToken)
				.build();
	}

	public String generateOtp(String email, String mobile) {
		if ((email == null || email.isEmpty()) && (mobile == null || mobile.isEmpty())) {
			throw new IllegalArgumentException("Either email or mobile must be provided");
		}

		String otp = String.valueOf(new Random().nextInt(999999)); // Generate a 6-digit OTP
		var otpRecord = Otp.builder()
				.email(email)
				.mobile(mobile)
				.otp(otp)
				.createdAt(LocalDateTime.now())
				.expiresAt(LocalDateTime.now().plusMinutes(5)) // Valid for 5 minutes
				.build();
		otpRepository.save(otpRecord);

		// Send OTP via email or SMS based on provided information
		if (email != null && !email.isEmpty()) {
			notificationService.sendEmailOtp(email, otp);
		}
//		} else if (mobile != null && !mobile.isEmpty()) {
//			notificationService.sendSmsOtp(mobile, otp);
//		}

		return "OTP sent successfully!";
	}


	public String getLoggedInUser() {
		System.out.println("Logged in user : "+SecurityContextHolder.getContext().getAuthentication().getDetails().toString());
		return SecurityContextHolder.getContext().getAuthentication().getName();
	}
}
