package org.chhan.ex_jwt.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.chhan.ex_jwt.domain.User;
import org.chhan.ex_jwt.dto.AuthDTO;
import org.chhan.ex_jwt.dto.JwtToken;
import org.chhan.ex_jwt.service.AuthService;
import org.chhan.ex_jwt.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Auth API")
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final UserService userService;

    @Operation(summary = "Login API")
    @PostMapping("/login")
    public ResponseEntity<JwtToken> login(@RequestBody AuthDTO.Login loginDTO, HttpServletResponse response) {
        JwtToken jwtToken = authService.login(loginDTO);

        String accessToken = jwtToken.getAccessToken();
        String refreshToken = jwtToken.getRefreshToken();

        Cookie accessCookie = new Cookie("access_token", accessToken);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(true);
        accessCookie.setPath("/");
        accessCookie.setMaxAge(3600);

        Cookie refreshCookie = new Cookie("refresh_token", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(3600);

        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);

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
    public ResponseEntity<String> tokenReissuance(@CookieValue(name = "access_token") String accessToken,
                                                  @CookieValue(name = "refresh_token") String refreshToken,
                                                  @RequestBody AuthDTO.TokenReissuance paramUser) {
        System.out.println("Access Token : " + accessToken);
        System.out.println("Refresh Token : " + refreshToken);
        User user = userService.findUserByUserId(paramUser.getId());

        if (user.getCurrentRefreshToken().equals(refreshToken)) {
            String tokenStatus = authService.refreshTokenCheck(refreshToken);
            if (tokenStatus.equals("R Success")) {
                return ResponseEntity.ok(authService.accessTokenReissuance(user));
            } else {
                return ResponseEntity.badRequest().body(tokenStatus);
            }
        } else {

        }

        return ResponseEntity.status(400).body("GG");
    }


}
