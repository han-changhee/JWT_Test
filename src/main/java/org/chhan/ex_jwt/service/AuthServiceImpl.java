package org.chhan.ex_jwt.service;

import lombok.RequiredArgsConstructor;
import org.chhan.ex_jwt.component.JwtTokenProvider;
import org.chhan.ex_jwt.domain.User;
import org.chhan.ex_jwt.dto.AuthDTO;
import org.chhan.ex_jwt.dto.JwtToken;
import org.chhan.ex_jwt.repository.UserRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository        userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public JwtToken login(AuthDTO.Login loginDTO) {
        // 1. Login Email/PW를 기반으로 Authentication 객체 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword());
        // 2. 실제 검증 (사용자 비밀번호 체크)
        // authenticate 메서드가 실행될 때 CustomUserDetailsService에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        // 3. 인증정보 기반으로 JWT 생성
        JwtToken jwtToken = jwtTokenProvider.generateToken(authentication);
        return jwtToken;
    }

    @Override
    public void updateRefreshToken(User user) {
        userRepository.updateUserRefreshToken(user);
    }

    @Override
    public long logOut(long id) {
        return userRepository.logOut(id);
    }

    @Override
    public String refreshTokenCheck(String token) {
        String tokenStatus = jwtTokenProvider.validateToken(token);

        return "R " + tokenStatus;
    }

    @Override
    public String accessTokenReissuance(User user) {
        return jwtTokenProvider.accessTokenReissuance(user);
    }

    @Override
    public User createUser(AuthDTO.Signup signupinfp) {
        User user = new User();

        String encodePassword = bCryptPasswordEncoder.encode(signupinfp.getPassword());
        user.setEmail(signupinfp.getEmail());
        user.setPassword(encodePassword);
        user.setAuthorityLevel(0);
        user.setRole("admin");

        User savedUser = userRepository.save(user);
        savedUser.setPassword("");

        return savedUser;
    }


}
