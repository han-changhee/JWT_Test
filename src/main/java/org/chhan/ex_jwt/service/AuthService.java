package org.chhan.ex_jwt.service;

import org.chhan.ex_jwt.domain.User;
import org.chhan.ex_jwt.dto.AuthDTO;
import org.chhan.ex_jwt.dto.JwtToken;

public interface AuthService {
    // login Token 발급
    JwtToken login(AuthDTO.Login loginDTO);

    // update refresh token
    void updateRefreshToken(User user);

    // logout
    long logOut(long id);

    // refreshToken check
    String refreshTokenCheck(String token);

    // accessToken Reissuance
    String accessTokenReissuance(User user);

    // create User
    User createUser(AuthDTO.Signup signupinfo);
}
