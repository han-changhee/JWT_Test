package org.chhan.ex_jwt.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.chhan.ex_jwt.advice.exception.JwtTokenException;
import org.chhan.ex_jwt.component.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider        jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.info("JwtAuthenticationFilter --- Filtering");
        // request 에서 JWT 토큰 추출
        String token = jwtTokenProvider.resolveToken(request);
        if (token != null) {
            // 토큰이 존재하는 경우 //
            // 1. 토큰 타입 확인 (Access Token / Refresh Token / 이상한 토큰인지 확인
            String tokenType = jwtTokenProvider.tokenTypeCheck(token);

            if (tokenType.equals("reT")) {
                // 1-1 Refresh Token
                throw new JwtTokenException("Check token value");
            }
            else if (tokenType.equals("acT")) {
                // 1-2 Access Token
                if (jwtTokenProvider.validateToken(token).equals("Success")) {
                    // Token 유효성 검사 통과
                    filterChain.doFilter(request, response);
                } else {
                    // Token 검사 실패
                    throw new JwtTokenException("JWT claims string is empty.");
                }
            }
        }
        else {
            // 토큰을 받지 않은 경우
            log.info("JwtAuthenticationFilter --- No token found");
            throw new JwtTokenException("ERR Token not found");
        }
    }
}
