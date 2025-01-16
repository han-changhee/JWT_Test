package org.chhan.ex_jwt.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
            String tokenType = jwtTokenProvider.tokenTypeCheck(token);

            if (tokenType.equals("reT")) {
                // refresh token을 받을 경우

                response.setStatus(HttpStatus.FORBIDDEN.value());
                response.getWriter().write("Check token value");
                return;
            }
            else if (tokenType.equals("acT")) {
                System.out.println(token);
                switch (jwtTokenProvider.validateToken(token)) {
                    case "Expired":
                        response.setStatus(HttpStatus.FORBIDDEN.value());
                        response.getWriter().write("A Expired");
                        break;
                    case "Invalid":
                        response.setStatus(HttpStatus.FORBIDDEN.value());
                        response.getWriter().write("A Invalid");
                        break;
                    default:
                        filterChain.doFilter(request, response);
                        break;
                }
            }


        }
        else {
            log.info("JwtAuthenticationFilter --- No token found");
            response.setStatus(403);
            response.getWriter().write("ERR_T_500"); //token is null
        }
    }
}
