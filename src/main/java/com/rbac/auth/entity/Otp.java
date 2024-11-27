package com.rbac.auth.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Otp {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String email;  // Optional, null if login is via mobile
    private String mobile; // Optional, null if login is via email
    private String otp;

    private LocalDateTime createdAt;
    @Getter
    private LocalDateTime expiresAt;

    @Getter
    @Setter
    private boolean used = false; // Flag to check if OTP is used
}
