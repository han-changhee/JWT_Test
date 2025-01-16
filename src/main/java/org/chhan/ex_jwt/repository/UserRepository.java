package org.chhan.ex_jwt.repository;

import org.chhan.ex_jwt.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long>, UserRepositoryCustom{
}
