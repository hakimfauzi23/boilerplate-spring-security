package com.hakimfauzi23.boilerplatespringsecurity.modules.auth.repository;

import com.hakimfauzi23.boilerplatespringsecurity.modules.auth.data.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

}
