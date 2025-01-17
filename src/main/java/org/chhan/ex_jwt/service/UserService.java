package org.chhan.ex_jwt.service;

import org.chhan.ex_jwt.domain.User;

public interface UserService {
    User findUserByEmail(String email);
    User findUserByUserId(Long id);
}
