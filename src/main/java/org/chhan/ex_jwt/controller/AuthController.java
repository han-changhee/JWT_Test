package org.chhan.ex_jwt.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.chhan.ex_jwt.domain.User;
import org.chhan.ex_jwt.dto.AuthDTO;
import org.chhan.ex_jwt.dto.JwtToken;
import org.chhan.ex_jwt.service.AuthService;
import org.chhan.ex_jwt.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Auth API")
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;

    private final AuthService authService;
    private final UserService userService;

    @Operation(summary = "Login API")
    @PostMapping("/login")
    public ResponseEntity<JwtToken> login(@RequestBody AuthDTO.Login loginDTO) {
        JwtToken jwtToken = authService.login(loginDTO);

        if (jwtToken != null) {
            authService.updateRefreshToken(jwtToken.getUser());
            System.out.println("jwt Token: " + jwtToken.getAccessToken());
            return ResponseEntity.ok(jwtToken);
        } else {
            System.out.println("jwt token is null");
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/signup")
    public ResponseEntity<?> singup(@RequestBody AuthDTO.Signup signupDTO) {
        User user = userService.findUserByEmail(signupDTO.getEmail());
        if (user == null) {
           User successUser = authService.createUser(signupDTO);

           return ResponseEntity.status(HttpStatus.CREATED).body(successUser);
        }
        return ResponseEntity.notFound().build();
    }

    @Operation(summary = "logout API")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody AuthDTO.LogOut logOutDTO) {
        return ResponseEntity.ok(authService.logOut(logOutDTO.getId()));
    }

    @Operation(summary = "Access Token 재발급")
    @PostMapping("/token/reissuance")
    public ResponseEntity<String> tokenReissuance(@RequestBody AuthDTO.TokenReissuance paramUser) {
        User user = userService.findUserByEmail(paramUser.getEmail());
        if (user.getCurrentRefreshToken().equals(paramUser.getCurrentRefreshToken())) {
            String tokenStatus = authService.refreshTokenCheck(paramUser.getCurrentRefreshToken());
            if (tokenStatus.equals("R Success")) {
                return ResponseEntity.ok(authService.accessTokenReissuance(user));
            } else {
                return ResponseEntity.badRequest().body(tokenStatus);
            }
        } else {
            return ResponseEntity.notFound().build();
        }
    }


}
