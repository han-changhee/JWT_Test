package org.chhan.ex_jwt.dto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.chhan.ex_jwt.domain.User;

@Builder
@Data
@AllArgsConstructor
public class JwtToken {
    @NotNull
    private String grantType;

    @NotNull
    private String accessToken;

    @NotNull
    private String refreshToken;

    @NotNull
    private User user;
}
