package com.hakimfauzi23.boilerplatespringsecurity.repository;

import com.hakimfauzi23.boilerplatespringsecurity.data.RefreshToken;
import com.hakimfauzi23.boilerplatespringsecurity.data.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUserId(Long userId);


    @Modifying
    int deleteByUser(User user);
}
