package org.chhan.ex_jwt.dto;

import lombok.Data;

public class AuthDTO {
    @Data
    public static class Login {
        private String email;
        private String password;
    }

    @Data
    public static class LogOut {
        private long id;
    }

    @Data
    public static class Signup {
        private String email;
        private String password;
    }

    @Data
    public static class TokenReissuance {
        private String email;
        private String currentRefreshToken;
    }
}
