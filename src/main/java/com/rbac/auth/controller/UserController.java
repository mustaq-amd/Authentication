package com.rbac.auth.controller;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rbac.auth.dto.ChangePasswordRequest;
import com.rbac.auth.service.UserService;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    private final UserService service;

    @PatchMapping
    public ResponseEntity<?> changePassword(
            @RequestBody ChangePasswordRequest request,
            Principal connectedUser
    ) {
        logger.info("Received request to change password for connected user");
        logger.debug("ChangePasswordRequest details: {}", request);

        try {
            service.changePassword(request, connectedUser);
            logger.info("Password successfully changed for user: {}", connectedUser.getName());
            return ResponseEntity.ok().build();
        } catch (IllegalStateException e) {
            logger.warn("Failed to change password: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error occurred while changing password", e);
            return ResponseEntity.status(500).body("An unexpected error occurred.");
        }
    }
}
