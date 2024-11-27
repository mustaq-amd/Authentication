package com.rbac.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rbac.auth.entity.User;

public interface UserRepository extends JpaRepository<User, String> {

	Optional<User> findByEmail(String email);

    Optional<User> findByMobile(String mobile);
}
