package com.hakimfauzi23.boilerplatespringsecurity.repository;

import com.hakimfauzi23.boilerplatespringsecurity.data.ERole;
import com.hakimfauzi23.boilerplatespringsecurity.data.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);

}
