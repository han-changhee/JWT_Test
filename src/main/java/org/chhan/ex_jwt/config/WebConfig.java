package org.chhan.ex_jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 모든 경로에 대해 CORS 허용
                .allowedOrigins("http://localhost:8082", "https://test.gnsson.com:8082") // 특정 Origin만 허용
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // 허용되는 HTTP 메서드
                .allowedHeaders("Authorization", "Content-Type", "Accept", "X-Requested-With", "cache-control", "Access-Control-Allow-Origin") // 허용되는 헤더
                .exposedHeaders("Custom-Header", "Authorization") // 클라이언트에서 접근 가능한 헤더
                .allowCredentials(true); // 요청에 인증 정보를 포함할지 여부 (필요한 경우 주석 해제)
    }
}
