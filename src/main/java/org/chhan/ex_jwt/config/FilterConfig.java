package org.chhan.ex_jwt.config;

import lombok.RequiredArgsConstructor;
import org.chhan.ex_jwt.auth.filter.JwtAuthenticationFilter;
import org.chhan.ex_jwt.component.JwtTokenProvider;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FilterConfig {
    private final JwtTokenProvider jwtTokenProvider;
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtAuthenticationFilter() {

        // JwtAuthenticationFilter가 적용되는 Url
        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();

        registrationBean.setFilter(new JwtAuthenticationFilter(jwtTokenProvider));
        registrationBean.setOrder(1);
        registrationBean.addUrlPatterns("/auth/logout", "/auth/token/reissuance");

        return registrationBean;
    }
}
