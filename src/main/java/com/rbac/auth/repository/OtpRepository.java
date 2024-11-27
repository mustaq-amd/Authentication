package com.rbac.auth.repository;

import com.rbac.auth.entity.Otp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OtpRepository extends JpaRepository<Otp, Long> {
    Optional<Otp> findByEmailAndOtpAndUsedFalse(String email, String otp);
    Optional<Otp> findByMobileAndOtpAndUsedFalse(String mobile, String otp);
}
