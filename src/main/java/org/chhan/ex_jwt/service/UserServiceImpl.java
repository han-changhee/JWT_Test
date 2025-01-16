package org.chhan.ex_jwt.service;

import lombok.RequiredArgsConstructor;
import org.chhan.ex_jwt.domain.User;
import org.chhan.ex_jwt.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public User findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}
