package com.spring_security.persistence.repository;

import com.spring_security.persistence.entity.UserEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserEntity,Long> {

    Optional<UserEntity> findUserEntityByUsername(String username);
}
