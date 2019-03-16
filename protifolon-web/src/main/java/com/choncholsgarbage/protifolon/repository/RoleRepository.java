package com.choncholsgarbage.protifolon.repository;

import com.choncholsgarbage.protifolon.enums.RoleName;
import com.choncholsgarbage.protifolon.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(RoleName roleName);
}
