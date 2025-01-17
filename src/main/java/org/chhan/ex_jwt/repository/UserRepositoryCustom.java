package org.chhan.ex_jwt.repository;

import org.chhan.ex_jwt.domain.User;

public interface UserRepositoryCustom {

    // Email 정보를 통해 DB에 존재하는 유저정보 가져오기
    User findByEmail(String email);

    User findByUserId(Long id);

    // RefreshToken 변경
    void updateUserRefreshToken(User user);

    // Logout시 RefreshToken null로 변경
    long logOut(long id);

}
