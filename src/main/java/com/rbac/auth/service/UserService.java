package com.rbac.auth.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.rbac.auth.dto.ChangePasswordRequest;
import com.rbac.auth.entity.User;
import com.rbac.auth.repository.UserRepository;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final PasswordEncoder passwordEncoder;
    private final UserRepository repository;

    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {
        logger.info("Initiating password change process for user: {}", connectedUser.getName());

        // Retrieve user from Principal
        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();
        logger.debug("Retrieved user details for user: {}", user.getEmail());

        // Check if the current password is correct
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            logger.warn("Password change failed for user: {}. Reason: Incorrect current password.", user.getEmail());
            throw new IllegalStateException("Wrong password");
        }
        logger.debug("Current password verified successfully for user: {}", user.getEmail());

        // Check if the two new passwords are the same
        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
            logger.warn("Password change failed for user: {}. Reason: New passwords do not match.", user.getEmail());
            throw new IllegalStateException("Passwords are not the same");
        }
        logger.debug("New passwords match for user: {}", user.getEmail());

        // Update the password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        logger.info("Password encoded successfully for user: {}", user.getEmail());

        // Save the new password
        repository.save(user);
        logger.info("Password changed successfully for user: {}", user.getEmail());
    }
}
