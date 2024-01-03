package com.hakimfauzi23.boilerplatespringsecurity.modules.auth.repository;

import com.hakimfauzi23.boilerplatespringsecurity.modules.auth.data.ERole;
import com.hakimfauzi23.boilerplatespringsecurity.modules.auth.data.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);

}
